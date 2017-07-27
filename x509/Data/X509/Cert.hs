-- |
-- Module      : Data.X509.Cert
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Certificate types and functions
--
{-# LANGUAGE FlexibleContexts #-}

module Data.X509.Cert (Certificate(..)) where

import Data.ASN1.Types
import Control.Applicative ((<$>), (<*>))
import Data.X509.Internal
import Data.X509.PublicKey
import Data.X509.AlgorithmIdentifier
import Data.X509.DistinguishedName
import Data.X509.ExtensionRaw
import Data.Hourglass

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

-- | X.509 Certificate type.
--
-- This type doesn't include the signature, it's describe in the RFC
-- as tbsCertificate.
data Certificate = Certificate
        { certVersion      :: Int                    -- ^ Version
        , certSerial       :: Integer                -- ^ Serial number
        , certSignatureAlg :: SignatureALG           -- ^ Signature algorithm
        , certIssuerDN     :: DistinguishedName      -- ^ Issuer DN
        , certValidity     :: (DateTime, DateTime)   -- ^ Validity period (UTC)
        , certSubjectDN    :: DistinguishedName      -- ^ Subject DN
        , certPubKey       :: PubKey                 -- ^ Public key
        , certExtensions   :: Extensions             -- ^ Extensions
        } deriving (Show,Eq)

instance ASN1Object Certificate where
    toASN1   certificate = \xs -> encodeCertificateHeader certificate ++ xs
    fromASN1 s           = runParseASN1State parseCertificate s

parseCertHeaderVersion :: ParseASN1 Int
parseCertHeaderVersion =
    maybe 0 id <$> onNextContainerMaybe (Container Context 0) (getNext >>= getVer)
  where getVer (IntVal v) = return $ fromIntegral v
        getVer _          = throwParseError "unexpected type for version"

parseCertHeaderSerial :: ParseASN1 Integer
parseCertHeaderSerial = do
    n <- getNext
    case n of
        IntVal v -> return v
        _        -> throwParseError ("missing serial" ++ show n)

parseCertHeaderValidity :: ParseASN1 (DateTime, DateTime)
parseCertHeaderValidity = getNextContainer Sequence >>= toTimeBound
  where toTimeBound [ ASN1Time _ t1 _, ASN1Time _ t2 _ ] = return (t1,t2)
        toTimeBound _                                    = throwParseError "bad validity format"

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
                <*> getObject

encodeCertificateHeader :: Certificate -> [ASN1]
encodeCertificateHeader cert =
    eVer ++ eSerial ++ eAlgId ++ eIssuer ++ eValidity ++ eSubject ++ epkinfo ++ eexts
  where eVer      = asn1Container (Container Context 0) [IntVal (fromIntegral $ certVersion cert)]
        eSerial   = [IntVal $ certSerial cert]
        eAlgId    = toASN1 (certSignatureAlg cert) []
        eIssuer   = toASN1 (certIssuerDN cert) []
        (t1, t2)  = certValidity cert
        eValidity = asn1Container Sequence [ASN1Time (timeType t1) t1 (Just (TimezoneOffset 0))
                                           ,ASN1Time (timeType t2) t2 (Just (TimezoneOffset 0))]
        eSubject  = toASN1 (certSubjectDN cert) []
        epkinfo   = toASN1 (certPubKey cert) []
        eexts     = toASN1 (certExtensions cert) []
        timeType t =
            if t >= timeConvert (Date 2050 January 1)
            then TimeGeneralized
            else TimeUTC
