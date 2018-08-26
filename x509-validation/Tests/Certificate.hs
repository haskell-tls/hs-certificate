{-# LANGUAGE GADTs #-}
-- | Types and functions used to build test certificates.
module Certificate
    (
    -- * Hash algorithms
      hashMD2
    , hashMD5
    , hashSHA1
    , hashSHA224
    , hashSHA256
    , hashSHA384
    , hashSHA512
    -- * Key and signature utilities
    , Alg(..)
    , Keys
    , generateKeys
    -- * Certificate utilities
    , Pair(..)
    , mkDn
    , mkExtension
    , leafStdExts
    -- * Certificate creation functions
    , Auth(..)
    , mkCertificate
    , mkCA
    , mkLeaf
    ) where

import Control.Applicative

import Crypto.Hash.Algorithms
import Crypto.Number.Serialize

import qualified Crypto.PubKey.DSA        as DSA
import qualified Crypto.PubKey.ECC.ECDSA  as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types  as ECC
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.Ed448      as Ed448
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.RSA.PSS    as PSS

import qualified Data.ByteString as B

import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Encoding
import Data.ASN1.Types
import Data.ByteArray (convert)
import Data.Maybe (catMaybes)
import Data.String (fromString)
import Data.X509

import Data.Hourglass


-- Crypto utilities --

-- | Hash algorithms supported in certificates.
--
-- This relates the typed hash algorithm @hash@ to the 'HashALG' value.
data GHash hash = GHash { getHashALG :: HashALG, getHashAlgorithm :: hash }

hashMD2    :: GHash MD2
hashMD5    :: GHash MD5
hashSHA1   :: GHash SHA1
hashSHA224 :: GHash SHA224
hashSHA256 :: GHash SHA256
hashSHA384 :: GHash SHA384
hashSHA512 :: GHash SHA512

hashMD2    = GHash HashMD2    MD2
hashMD5    = GHash HashMD5    MD5
hashSHA1   = GHash HashSHA1   SHA1
hashSHA224 = GHash HashSHA224 SHA224
hashSHA256 = GHash HashSHA256 SHA256
hashSHA384 = GHash HashSHA384 SHA384
hashSHA512 = GHash HashSHA512 SHA512

-- | Signature and hash algorithms instantiated with parameters.
data Alg pub priv where
    AlgRSA    :: (HashAlgorithm hash, RSA.HashAlgorithmASN1 hash)
              => Int
              -> GHash hash
              -> Alg RSA.PublicKey RSA.PrivateKey

    AlgRSAPSS :: HashAlgorithm hash
              => Int
              -> PSS.PSSParams hash B.ByteString B.ByteString
              -> GHash hash
              -> Alg RSA.PublicKey RSA.PrivateKey

    AlgDSA    :: HashAlgorithm hash
              => DSA.Params
              -> GHash hash
              -> Alg DSA.PublicKey DSA.PrivateKey

    AlgEC     :: HashAlgorithm hash
              => ECC.CurveName
              -> GHash hash
              -> Alg ECDSA.PublicKey ECDSA.PrivateKey

    AlgEd25519 :: Alg Ed25519.PublicKey Ed25519.SecretKey

    AlgEd448   :: Alg Ed448.PublicKey Ed448.SecretKey

-- | Types of public and private keys used by a signature algorithm.
type Keys pub priv = (Alg pub priv, pub, priv)

-- | Generates random keys for a signature algorithm.
generateKeys :: Alg pub priv -> IO (Keys pub priv)
generateKeys alg@(AlgRSA bits      _) = generateRSAKeys alg bits
generateKeys alg@(AlgRSAPSS bits _ _) = generateRSAKeys alg bits
generateKeys alg@(AlgDSA params    _) = do
    x <- DSA.generatePrivate params
    let y = DSA.calculatePublic params x
    return (alg, DSA.PublicKey params y, DSA.PrivateKey params x)
generateKeys alg@(AlgEC name       _) = do
    let curve = ECC.getCurveByName name
    (pub, priv) <- ECC.generate curve
    return (alg, pub, priv)
generateKeys alg@AlgEd25519           = do
    secret <- Ed25519.generateSecretKey
    return (alg, Ed25519.toPublic secret, secret)
generateKeys alg@AlgEd448             = do
    secret <- Ed448.generateSecretKey
    return (alg, Ed448.toPublic secret, secret)

generateRSAKeys :: Alg RSA.PublicKey RSA.PrivateKey
                -> Int
                -> IO (Alg RSA.PublicKey RSA.PrivateKey, RSA.PublicKey, RSA.PrivateKey)
generateRSAKeys alg bits = addAlg <$> RSA.generate size e
  where
    addAlg (pub, priv) = (alg, pub, priv)
    size = bits `div` 8
    e    = 3

getPubKey :: Alg pub priv -> pub -> PubKey
getPubKey (AlgRSA    _    _) key = PubKeyRSA key
getPubKey (AlgRSAPSS _ _  _) key = PubKeyRSA key
getPubKey (AlgDSA    _    _) key = PubKeyDSA key
getPubKey (AlgEC     name _) key = PubKeyEC (PubKeyEC_Named name pub)
  where
    ECC.Point x y = ECDSA.public_q key
    pub   = SerializedPoint bs
    bs    = B.cons 4 (i2ospOf_ bytes x `B.append` i2ospOf_ bytes y)
    bits  = ECC.curveSizeBits (ECC.getCurveByName name)
    bytes = (bits + 7) `div` 8
getPubKey  AlgEd25519        key = PubKeyEd25519   key
getPubKey  AlgEd448          key = PubKeyEd448     key

getSignatureALG :: Alg pub priv -> SignatureALG
getSignatureALG (AlgRSA    _   hash) = SignatureALG (getHashALG hash) PubKeyALG_RSA
getSignatureALG (AlgRSAPSS _ _ hash) = SignatureALG (getHashALG hash) PubKeyALG_RSAPSS
getSignatureALG (AlgDSA    _   hash) = SignatureALG (getHashALG hash) PubKeyALG_DSA
getSignatureALG (AlgEC     _   hash) = SignatureALG (getHashALG hash) PubKeyALG_EC
getSignatureALG  AlgEd25519          = SignatureALG_IntrinsicHash PubKeyALG_Ed25519
getSignatureALG  AlgEd448            = SignatureALG_IntrinsicHash PubKeyALG_Ed448

doSign :: Alg pub priv -> priv -> B.ByteString -> IO B.ByteString
doSign (AlgRSA _ hash)        key msg = do
    result <- RSA.signSafer (Just $ getHashAlgorithm hash) key msg
    case result of
        Left err      -> error ("doSign(AlgRSA): " ++ show err)
        Right sigBits -> return sigBits
doSign (AlgRSAPSS _ params _) key msg = do
    result <- PSS.signSafer params key msg
    case result of
        Left err      -> error ("doSign(AlgRSAPSS): " ++ show err)
        Right sigBits -> return sigBits
doSign (AlgDSA _ hash)        key msg = do
    sig <- DSA.sign key (getHashAlgorithm hash) msg
    return $ encodeASN1' DER
                 [ Start Sequence
                 , IntVal (DSA.sign_r sig)
                 , IntVal (DSA.sign_s sig)
                 , End Sequence
                 ]
doSign (AlgEC _ hash)         key msg = do
    sig <- ECDSA.sign key (getHashAlgorithm hash) msg
    return $ encodeASN1' DER
                 [ Start Sequence
                 , IntVal (ECDSA.sign_r sig)
                 , IntVal (ECDSA.sign_s sig)
                 , End Sequence
                 ]
doSign  AlgEd25519            key msg =
    return $ convert $ Ed25519.sign key (Ed25519.toPublic key) msg
doSign  AlgEd448              key msg =
    return $ convert $ Ed448.sign key (Ed448.toPublic key) msg


-- Certificate utilities --

-- | Holds together a certificate and its private key for convenience.
--
-- Contains also the crypto algorithm that both are issued from.  This is
-- useful when signing another certificate.
data Pair pub priv = Pair
    { pairAlg        :: Alg pub priv
    , pairSignedCert :: SignedCertificate
    , pairKey        :: priv
    }

-- | Builds a DN with a single component.
mkDn :: String -> DistinguishedName
mkDn cn = DistinguishedName [(getObjectID DnCommonName, fromString cn)]

-- | Used to build a certificate extension.
mkExtension :: Extension a => Bool -> a -> ExtensionRaw
mkExtension crit ext = ExtensionRaw (extOID ext) crit (extEncodeBs ext)

-- | Default extensions in leaf certificates.
leafStdExts :: [ExtensionRaw]
leafStdExts = [ku, eku]
  where
    ku  = mkExtension False $ ExtKeyUsage
               [ KeyUsage_digitalSignature , KeyUsage_keyEncipherment ]
    eku = mkExtension False $ ExtExtendedKeyUsage
               [ KeyUsagePurpose_ServerAuth , KeyUsagePurpose_ClientAuth ]


-- Authority signing a certificate --
--
-- When the certificate is self-signed, issuer and subject are the same.  So
-- they have identical signature algorithms.  The purpose of the GADT is to
-- hold this constraint only in the self-signed case.

-- | Authority signing a certificate, itself or another certificate.
data Auth pubI privI pubS privS where
    Self :: (pubI ~ pubS, privI ~ privS) => Auth pubI privI pubS privS
    CA   ::              Pair pubI privI -> Auth pubI privI pubS privS

foldAuth :: a
         -> (Pair pubI privI -> a)
         -> Auth pubI privI pubS privS
         -> a
foldAuth x _ Self   = x          -- no constraint used
foldAuth _ f (CA p) = f p

foldAuthPriv :: privS
             -> (Pair pubI privI -> privI)
             -> Auth pubI privI pubS privS
             -> privI
foldAuthPriv x _ Self   = x      -- uses constraint privI ~ privS
foldAuthPriv _ f (CA p) = f p

foldAuthPubPriv :: k pubS privS
                -> (Pair pubI privI -> k pubI privI)
                -> Auth pubI privI pubS privS
                -> k pubI privI
foldAuthPubPriv x _ Self   = x   -- uses both constraints
foldAuthPubPriv _ f (CA p) = f p


-- Certificate creation functions --

-- | Builds a certificate using the supplied keys and signs it with an
-- authority (itself or another certificate).
mkCertificate :: Int                        -- ^ Certificate version
              -> Integer                    -- ^ Serial number
              -> DistinguishedName          -- ^ Subject DN
              -> (DateTime, DateTime)       -- ^ Certificate validity period
              -> [ExtensionRaw]             -- ^ Extensions to include
              -> Auth pubI privI pubS privS -- ^ Authority signing the new certificate
              -> Keys pubS privS            -- ^ Keys for the new certificate
              -> IO (Pair pubS privS)       -- ^ The new certificate/key pair
mkCertificate version serial dn validity exts auth (algS, pubKey, privKey) = do
    signedCert <- objectToSignedExactF signatureFunction cert
    return Pair { pairAlg        = algS
                , pairSignedCert = signedCert
                , pairKey        = privKey
                }

  where
    pairCert = signedObject . getSigned . pairSignedCert

    cert = Certificate
        { certVersion      = version
        , certSerial       = serial
        , certSignatureAlg = signAlgI
        , certIssuerDN     = issuerDN
        , certValidity     = validity
        , certSubjectDN    = dn
        , certPubKey       = getPubKey algS pubKey
        , certExtensions   = extensions
        }

    signingKey = foldAuthPriv     privKey pairKey auth
    algI       = foldAuthPubPriv  algS    pairAlg auth

    signAlgI   = getSignatureALG algI
    issuerDN   = foldAuth dn (certSubjectDN . pairCert) auth
    extensions = Extensions (if null exts then Nothing else Just exts)

    signatureFunction objRaw = do
        sigBits <- doSign algI signingKey objRaw
        return (sigBits, signAlgI)

-- | Builds a CA certificate using the supplied keys and signs it with an
-- authority (itself or another certificate).
mkCA :: Integer                    -- ^ Serial number
     -> String                     -- ^ Common name
     -> (DateTime, DateTime)       -- ^ CA validity period
     -> Maybe ExtBasicConstraints  -- ^ CA basic constraints
     -> Maybe ExtKeyUsage          -- ^ CA key usage
     -> Auth pubI privI pubS privS -- ^ Authority signing the new certificate
     -> Keys pubS privS            -- ^ Keys for the new certificate
     -> IO (Pair pubS privS)       -- ^ The new CA certificate/key pair
mkCA serial cn validity bc ku =
    let exts = catMaybes [ mkExtension True <$> bc, mkExtension False <$> ku ]
    in mkCertificate 2 serial (mkDn cn) validity exts

-- | Builds a leaf certificate using the supplied keys and signs it with an
-- authority (itself or another certificate).
mkLeaf :: String                     -- ^ Common name
       -> (DateTime, DateTime)       -- ^ Certificate validity period
       -> Auth pubI privI pubS privS -- ^ Authority signing the new certificate
       -> Keys pubS privS            -- ^ Keys for the new certificate
       -> IO (Pair pubS privS)       -- ^ The new leaf certificate/key pair
mkLeaf cn validity = mkCertificate 2 100 (mkDn cn) validity leafStdExts
