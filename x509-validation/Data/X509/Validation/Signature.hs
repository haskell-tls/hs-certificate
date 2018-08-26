-- |
-- Module      : Data.X509.Validation.Signature
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Certificate and CRL signature verification
--
module Data.X509.Validation.Signature
    ( verifySignedSignature
    , verifySignature
    , SignatureVerification(..)
    , SignatureFailure(..)
    ) where

import Crypto.Error (CryptoFailable(..))
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.RSA.PSS as PSS
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import Crypto.Hash

import Data.ByteString (ByteString)
import Data.X509
import Data.X509.EC
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding

-- | A set of possible return from signature verification.
--
-- When SignatureFailed is return, the signature shouldn't be
-- accepted.
--
-- Other values are only useful to differentiate the failure
-- reason, but are all equivalent to failure.
--
data SignatureVerification =
      SignaturePass                    -- ^ verification succeeded
    | SignatureFailed SignatureFailure -- ^ verification failed
    deriving (Show,Eq)

-- | Various failure possible during signature checking
data SignatureFailure =
      SignatureInvalid        -- ^ signature doesn't verify
    | SignaturePubkeyMismatch -- ^ algorithm and public key mismatch, cannot proceed
    | SignatureUnimplemented  -- ^ unimplemented signature algorithm
    deriving (Show,Eq)

-- | Verify a Signed object against a specified public key
verifySignedSignature :: (Show a, Eq a, ASN1Object a)
                      => SignedExact a
                      -> PubKey
                      -> SignatureVerification
verifySignedSignature signedObj pubKey =
    verifySignature (signedAlg signed)
                    pubKey
                    (getSignedData signedObj)
                    (signedSignature signed)
  where signed = getSigned signedObj

-- | verify signature using parameter
verifySignature :: SignatureALG -- ^ Signature algorithm used
                -> PubKey       -- ^ Public key to use for verify
                -> ByteString   -- ^ Certificate data that need to be verified
                -> ByteString   -- ^ Signature to verify
                -> SignatureVerification
verifySignature (SignatureALG_Unknown _) _ _ _ = SignatureFailed SignatureUnimplemented
verifySignature (SignatureALG hashALG PubKeyALG_RSAPSS) pubkey cdata signature = case verifyF pubkey of
  Nothing    -> SignatureFailed SignatureUnimplemented
  Just f -> if f cdata signature
               then SignaturePass
               else SignatureFailed SignatureInvalid
  where
    verifyF (PubKeyRSA key)
      | hashALG == HashSHA256 = Just $ PSS.verify (PSS.defaultPSSParams SHA256) key
      | hashALG == HashSHA384 = Just $ PSS.verify (PSS.defaultPSSParams SHA384) key
      | hashALG == HashSHA512 = Just $ PSS.verify (PSS.defaultPSSParams SHA512) key
      | hashALG == HashSHA224 = Just $ PSS.verify (PSS.defaultPSSParams SHA224) key
      | otherwise             = Nothing
    verifyF _                 = Nothing
verifySignature (SignatureALG hashALG pubkeyALG) pubkey cdata signature
    | pubkeyToAlg pubkey == pubkeyALG = case verifyF pubkey of
                                            Nothing -> SignatureFailed SignatureUnimplemented
                                            Just f  -> if f cdata signature
                                                            then SignaturePass
                                                            else SignatureFailed SignatureInvalid
    | otherwise                       = SignatureFailed SignaturePubkeyMismatch
  where
        verifyF (PubKeyRSA key) = Just $ rsaVerify hashALG key
        verifyF (PubKeyDSA key)
            | hashALG == HashSHA1   = Just $ dsaVerify SHA1   key
            | hashALG == HashSHA224 = Just $ dsaVerify SHA224 key
            | hashALG == HashSHA256 = Just $ dsaVerify SHA256 key
            | otherwise           = Nothing
        verifyF (PubKeyEC key) = verifyECDSA hashALG key
        verifyF _ = Nothing

        dsaToSignature :: ByteString -> Maybe DSA.Signature
        dsaToSignature b =
            case decodeASN1' BER b of
                Left _     -> Nothing
                Right asn1 ->
                    case asn1 of
                        Start Sequence:IntVal r:IntVal s:End Sequence:_ ->
                            Just $ DSA.Signature { DSA.sign_r = r, DSA.sign_s = s }
                        _ ->
                            Nothing

        dsaVerify hsh key b a =
            case dsaToSignature a of
                Nothing     -> False
                Just dsaSig -> DSA.verify hsh key dsaSig b

        rsaVerify HashMD2    = RSA.verify (Just MD2)
        rsaVerify HashMD5    = RSA.verify (Just MD5)
        rsaVerify HashSHA1   = RSA.verify (Just SHA1)
        rsaVerify HashSHA224 = RSA.verify (Just SHA224)
        rsaVerify HashSHA256 = RSA.verify (Just SHA256)
        rsaVerify HashSHA384 = RSA.verify (Just SHA384)
        rsaVerify HashSHA512 = RSA.verify (Just SHA512)

verifySignature (SignatureALG_IntrinsicHash pubkeyALG) pubkey cdata signature
    | pubkeyToAlg pubkey == pubkeyALG = doVerify pubkey
    | otherwise = SignatureFailed SignaturePubkeyMismatch
  where
    doVerify (PubKeyEd25519 key) = eddsa Ed25519.verify Ed25519.signature key
    doVerify (PubKeyEd448 key)   = eddsa Ed448.verify Ed448.signature key
    doVerify _                   = SignatureFailed SignatureUnimplemented

    eddsa verify toSig key =
        case toSig signature of
            CryptoPassed sig
                | verify key cdata sig -> SignaturePass
                | otherwise            -> SignatureFailed SignatureInvalid
            CryptoFailed _             -> SignatureFailed SignatureInvalid

verifyECDSA :: HashALG -> PubKeyEC -> Maybe (ByteString -> ByteString -> Bool)
verifyECDSA hashALG key =
    ecPubKeyCurveName key >>= verifyCurve (pubkeyEC_pub key)
  where
        verifyCurve pub curveName = Just $ \msg sigBS ->
            case decodeASN1' BER sigBS of
                Left _ -> False
                Right [Start Sequence,IntVal r,IntVal s,End Sequence] ->
                    let curve = ECC.getCurveByName curveName
                     in case unserializePoint curve pub of
                            Nothing -> False
                            Just p  -> let pubkey = ECDSA.PublicKey curve p
                                        in (ecdsaVerify hashALG) pubkey (ECDSA.Signature r s) msg
                Right _ -> False

        ecdsaVerify HashMD2    = ECDSA.verify MD2
        ecdsaVerify HashMD5    = ECDSA.verify MD5
        ecdsaVerify HashSHA1   = ECDSA.verify SHA1
        ecdsaVerify HashSHA224 = ECDSA.verify SHA224
        ecdsaVerify HashSHA256 = ECDSA.verify SHA256
        ecdsaVerify HashSHA384 = ECDSA.verify SHA384
        ecdsaVerify HashSHA512 = ECDSA.verify SHA512
