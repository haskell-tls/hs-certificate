-- |
-- Module      : Data.X509.Cert
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Certificate types and functions
module Data.X509.Cert
    (
    -- * Data Structure
      Certificate(..)
    ) where

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.Maybe
import Data.Time.Clock (UTCTime)
import Control.Applicative ((<$>), (<*>))
import Control.Monad.Error
import Data.X509.Internal
import Data.X509.Ext
import Data.X509.PublicKey
import Data.X509.AlgorithmIdentifier
import Data.X509.DistinguishedName

data CertKeyUsage =
          CertKeyUsageDigitalSignature
        | CertKeyUsageNonRepudiation
        | CertKeyUsageKeyEncipherment
        | CertKeyUsageDataEncipherment
        | CertKeyUsageKeyAgreement
        | CertKeyUsageKeyCertSign
        | CertKeyUsageCRLSign
        | CertKeyUsageEncipherOnly
        | CertKeyUsageDecipherOnly
        deriving (Show, Eq)

data Certificate = Certificate
        { certVersion      :: Int                    -- ^ Certificate Version
        , certSerial       :: Integer                -- ^ Certificate Serial number
        , certSignatureAlg :: SignatureALG           -- ^ Certificate Signature algorithm
        , certIssuerDN     :: DistinguishedName      -- ^ Certificate Issuer DN
        , certValidity     :: (UTCTime, UTCTime)     -- ^ Certificate Validity period
        , certSubjectDN    :: DistinguishedName      -- ^ Certificate Subject DN
        , certPubKey       :: PubKey                 -- ^ Certificate Public key
        , certExtensions   :: Maybe [ExtensionRaw]   -- ^ Certificate Extensions
        } deriving (Show,Eq)

instance ASN1Object Certificate where
    toASN1   certificate = \xs -> encodeCertificateHeader certificate ++ xs
    fromASN1 s           = runParseASN1State parseCertificate s

parseCertHeaderVersion :: ParseASN1 Int
parseCertHeaderVersion =
    maybe 1 id <$> onNextContainerMaybe (Container Context 0) (getNext >>= getVer)
  where getVer (IntVal v) = return $ fromIntegral v
        getVer _          = throwError "unexpected type for version"

parseCertHeaderSerial :: ParseASN1 Integer
parseCertHeaderSerial = do
    n <- getNext
    case n of
        IntVal v -> return v
        _        -> throwError ("missing serial" ++ show n)

parseCertHeaderValidity :: ParseASN1 (UTCTime, UTCTime)
parseCertHeaderValidity = getNextContainer Sequence >>= toTimeBound
  where toTimeBound [ ASN1Time _ t1 _, ASN1Time _ t2 _ ] = return (t1,t2)
        toTimeBound _                                    = throwError "bad validity format"

parseCertExtensions :: ParseASN1 (Maybe [ExtensionRaw])
parseCertExtensions =
    onNextContainerMaybe (Container Context 3)
                         (mapMaybe extractExtension <$> onNextContainer Sequence getSequences)
  where getSequences = do
            n <- hasNext
            if n
                then getNextContainer Sequence >>= \sq -> liftM (sq :) getSequences
                else return []
        extractExtension [OID oid,Boolean True,OctetString obj] =
            case decodeASN1' BER obj of
                Left _  -> Nothing
                Right r -> Just (oid, False, r)
        extractExtension [OID oid,OctetString obj]              =
            case decodeASN1' BER obj of
                Left _  -> Nothing
                Right r -> Just (oid, False, r)
        extractExtension _                                      =
            Nothing

{- | parse header structure of a x509 certificate. the structure is the following:
        Version
        Serial Number
        Algorithm ID
        Issuer
        Validity
                Not Before
                Not After
        Subject
        Subject Public Key Info
                Public Key Algorithm
                Subject Public Key
        Issuer Unique Identifier (Optional)  (>= 2)
        Subject Unique Identifier (Optional) (>= 2)
        Extensions (Optional)   (>= v3)
-}
parseCertificate :: ParseASN1 Certificate
parseCertificate =
    Certificate <$> parseCertHeaderVersion
                <*> parseCertHeaderSerial
                <*> getObject
                <*> getObject
                <*> parseCertHeaderValidity
                <*> getObject
                <*> getObject
                <*> parseCertExtensions
        
encodeExts :: Maybe [ExtensionRaw] -> [ASN1]
encodeExts Nothing  = []
encodeExts (Just l) = asn1Container (Container Context 3) $ concatMap encodeExt l
  where encodeExt (oid, critical, asn1) =
            let bs = encodeASN1' DER asn1
             in asn1Container Sequence ([OID oid] ++ (if critical then [Boolean True] else []) ++ [OctetString bs])

encodeCertificateHeader :: Certificate -> [ASN1]
encodeCertificateHeader cert =
    eVer ++ eSerial ++ eAlgId ++ eIssuer ++ eValidity ++ eSubject ++ epkinfo ++ eexts
  where eVer      = asn1Container (Container Context 0) [IntVal (fromIntegral $ certVersion cert)]
        eSerial   = [IntVal $ certSerial cert]
        eAlgId    = toASN1 (certSignatureAlg cert) []
        eIssuer   = toASN1 (certIssuerDN cert) []
        (t1, t2)  = certValidity cert
        eValidity = asn1Container Sequence [ASN1Time TimeGeneralized t1 Nothing
                                           ,ASN1Time TimeGeneralized t2 Nothing]
        eSubject  = toASN1 (certSubjectDN cert) []
        epkinfo   = toASN1 (certPubKey cert) []
        eexts     = encodeExts $ certExtensions cert
