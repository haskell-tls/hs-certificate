module Data.X509.Cert
        (
        -- * Data Structure
          SignatureALG(..)
        , HashALG(..)
        , PubKeyALG(..)
        , PubKey(..)
        , ECDSA_Hash(..)
        , Certificate(..)
        , DistinguishedName(..)
        , OID

        -- various OID
        , oidCommonName
        , oidCountry
        , oidOrganization
        , oidOrganizationUnit

        -- signature to/from oid
        , oidSig
        , sigOID

        -- * Parse and encode a single distinguished name
        , parseDN
        , encodeDNinner
        , encodeDN

        -- * extensions
        , module Data.X509.Ext
        ) where

import Data.Monoid
import Data.List (find)
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
import Data.Maybe
import Data.Time.Clock (UTCTime)
import qualified Data.ByteString as B
import Control.Applicative ((<$>))
import Control.Monad.State
import Control.Monad.Error
import Data.X509.Internal
import Data.X509.Ext
import Data.X509.PublicKey

import qualified Crypto.Types.PubKey.DSA as DSA

data HashALG =
          HashMD2
        | HashMD5
        | HashSHA1
        | HashSHA224
        | HashSHA256
        | HashSHA384
        | HashSHA512
        deriving (Show,Eq)

data SignatureALG =
          SignatureALG HashALG PubKeyALG
        | SignatureALG_Unknown OID
        deriving (Show,Eq)

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

newtype DistinguishedName = DistinguishedName { getDistinguishedElements :: [(OID, ASN1Stringable)] }
    deriving (Show,Eq)

instance Monoid DistinguishedName where
    mempty  = DistinguishedName []
    mappend (DistinguishedName l1) (DistinguishedName l2) = DistinguishedName (l1++l2)

data Certificate = Certificate
        { certVersion      :: Int                    -- ^ Certificate Version
        , certSerial       :: Integer                -- ^ Certificate Serial number
        , certSignatureAlg :: SignatureALG           -- ^ Certificate Signature algorithm
        , certIssuerDN     :: DistinguishedName      -- ^ Certificate Issuer DN
        , certSubjectDN    :: DistinguishedName      -- ^ Certificate Subject DN
        , certValidity     :: (UTCTime, UTCTime)     -- ^ Certificate Validity period
        , certPubKey       :: PubKey                 -- ^ Certificate Public key
        , certExtensions   :: Maybe [ExtensionRaw]   -- ^ Certificate Extensions
        } deriving (Show,Eq)

instance ASN1Object Certificate where
    toASN1   certificate = \xs -> encodeCertificateHeader certificate ++ xs
    fromASN1 s           = runParseASN1State parseCertificate s

oidCommonName, oidCountry, oidOrganization, oidOrganizationUnit :: OID
oidCommonName       = [2,5,4,3]
oidCountry          = [2,5,4,6]
oidOrganization     = [2,5,4,10]
oidOrganizationUnit = [2,5,4,11]

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

sig_table :: [ (OID, SignatureALG) ]
sig_table =
        [ ([1,2,840,113549,1,1,5], SignatureALG HashSHA1 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,4], SignatureALG HashMD5 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,2], SignatureALG HashMD2 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,11], SignatureALG HashSHA256 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,12], SignatureALG HashSHA384 PubKeyALG_RSA)
        , ([1,2,840,10040,4,3],    SignatureALG HashSHA1 PubKeyALG_DSA)
        , ([1,2,840,10045,4,3,1],  SignatureALG HashSHA224 PubKeyALG_ECDSA)
        , ([1,2,840,10045,4,3,2],  SignatureALG HashSHA256 PubKeyALG_ECDSA)
        , ([1,2,840,10045,4,3,3],  SignatureALG HashSHA384 PubKeyALG_ECDSA)
        , ([1,2,840,10045,4,3,4],  SignatureALG HashSHA512 PubKeyALG_ECDSA)
        ]

oidSig :: OID -> SignatureALG
oidSig oid = maybe (SignatureALG_Unknown oid) id $ lookup oid sig_table

oidPubKey :: OID -> PubKeyALG
oidPubKey oid =
    maybe (PubKeyALG_Unknown oid) id $ find (\p -> getObjectID p == oid) knownPubkeyAlgs

sigOID :: SignatureALG -> OID
sigOID (SignatureALG_Unknown oid) = oid
sigOID sig = maybe [] fst $ find ((==) sig . snd) sig_table

parseCertHeaderAlgorithmID :: ParseASN1 SignatureALG
parseCertHeaderAlgorithmID = do
    n <- getNextContainer Sequence
    case n of
        [ OID oid, Null ] -> return $ oidSig oid
        [ OID oid ]       -> return $ oidSig oid
        _                 -> throwError ("algorithm ID bad format " ++ show n)

type ASN1Stringable = (ASN1StringEncoding, B.ByteString)

parseDN :: ParseASN1 DistinguishedName
parseDN = DistinguishedName <$> onNextContainer Sequence getDNs
  where getDNs = do
            n <- hasNext
            if n
                then liftM2 (:) parseOneDN getDNs
                else return []

parseOneDN :: ParseASN1 (OID, ASN1Stringable)
parseOneDN = onNextContainer Set $ do
    s <- getNextContainer Sequence
    case s of
        [OID oid, ASN1String encoding val] -> return (oid, (encoding, val))
        _                                  -> throwError "expecting sequence"

parseCertHeaderValidity :: ParseASN1 (UTCTime, UTCTime)
parseCertHeaderValidity = getNextContainer Sequence >>= toTimeBound
  where toTimeBound [ ASN1Time _ t1 _, ASN1Time _ t2 _ ] = return (t1,t2)
        toTimeBound _                                    = throwError "bad validity format"

parseCertHeaderSubjectPK :: ParseASN1 PubKey
parseCertHeaderSubjectPK = onNextContainer Sequence $ do
    l <- getNextContainer Sequence
    bits <- getNextBitString
    case l of
        (OID pkalg):xs -> toKey (oidPubKey pkalg) xs bits
        _              -> throwError ("subject public unknown key format : " ++ show l)
  where toKey PubKeyALG_RSA _ bits = do
            case decodeASN1' BER bits of
                Left err -> throwError ("rsa format not ASN1: " ++ show err)
                Right s  -> case fromASN1 s of
                                Left err2     -> throwError err2
                                Right (rsa,_) -> return $ PubKeyRSA rsa
        toKey PubKeyALG_ECDSA xs bits = do
            case xs of
                [(OID [1,3,132,0,34])] -> return $ PubKeyECDSA ECDSA_Hash_SHA384 bits
                _                      -> return $ PubKeyUnknown (getObjectID PubKeyALG_ECDSA) $ B.unpack bits
        toKey PubKeyALG_DSA [Start Sequence,IntVal p,IntVal q,IntVal g,End Sequence] bits = do
            case decodeASN1' BER bits of
                Right [IntVal dsapub] -> return $ PubKeyDSA $ DSA.PublicKey
                                                                   { DSA.public_params = DSA.Params { DSA.params_p = p
                                                                                                    , DSA.params_q = q
                                                                                                    , DSA.params_g = g
                                                                                                    }
                                                                   , DSA.public_y = dsapub }
                _                     -> return $ PubKeyUnknown (getObjectID PubKeyALG_DSA) $ B.unpack bits
        toKey (PubKeyALG_Unknown oid) _ bits = return $ PubKeyUnknown oid $ B.unpack bits
        toKey other _ bits = return $ PubKeyUnknown (getObjectID other) $ B.unpack bits

        getNextBitString = getNext >>= \bs -> case bs of
            BitString bits -> return $ bitArrayGetData bits
            _              -> throwError "expecting bitstring"

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
                Right r -> Just (oid, True, r)
        extractExtension [OID oid,OctetString obj]              =
            case decodeASN1' BER obj of
                Left _  -> Nothing
                Right r -> Just (oid, False, r)
        extractExtension _                                      =
            Nothing

{- | parse header structure of a x509 certificate. the structure the following:
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
parseCertificate = do
        version  <- parseCertHeaderVersion
        serial   <- parseCertHeaderSerial
        sigalg   <- parseCertHeaderAlgorithmID
        issuer   <- parseDN
        validity <- parseCertHeaderValidity
        subject  <- parseDN
        pk       <- parseCertHeaderSubjectPK
        exts     <- parseCertExtensions
        hnext    <- hasNext
        when hnext $ throwError "expecting End Of Data."
        
        return $ Certificate
                { certVersion      = version
                , certSerial       = serial
                , certSignatureAlg = sigalg
                , certIssuerDN     = issuer
                , certSubjectDN    = subject
                , certValidity     = validity
                , certPubKey       = pk
                , certExtensions   = exts
                }

encodeDNinner :: (ASN1Stringable -> ASN1Stringable) -> DistinguishedName -> [ASN1]
encodeDNinner f (DistinguishedName dn) = concatMap dnSet dn
  where dnSet (oid, str) = asn1Container Set $ asn1Container Sequence [OID oid, uncurry ASN1String $ f str]

encodeDN :: DistinguishedName -> [ASN1]
encodeDN dn = asn1Container Sequence $ encodeDNinner id dn

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
        eAlgId    = asn1Container Sequence [OID (sigOID $ certSignatureAlg cert), Null]
        eIssuer   = encodeDN $ certIssuerDN cert
        (t1, t2)  = certValidity cert
        eValidity = asn1Container Sequence [ASN1Time TimeGeneralized t1 Nothing
                                           ,ASN1Time TimeGeneralized t2 Nothing]
        eSubject  = encodeDN $ certSubjectDN cert
        epkinfo   = encodePK $ certPubKey cert
        eexts     = encodeExts $ certExtensions cert
