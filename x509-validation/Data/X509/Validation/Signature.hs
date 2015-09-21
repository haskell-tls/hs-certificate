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

import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.Hash
import Crypto.Number.Basic (numBits)
import Crypto.Number.Serialize (os2ip)

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.X509
import Data.List (find)
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
            | hashALG == HashSHA1 = Just $ \a b -> case dsaToSignature a of
                                                    Nothing     -> False
                                                    Just dsaSig -> DSA.verify SHA1 key dsaSig b
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

        rsaVerify HashMD2    = RSA.verify (Just MD2)
        rsaVerify HashMD5    = RSA.verify (Just MD5)
        rsaVerify HashSHA1   = RSA.verify (Just SHA1)
        rsaVerify HashSHA224 = RSA.verify (Just SHA224)
        rsaVerify HashSHA256 = RSA.verify (Just SHA256)
        rsaVerify HashSHA384 = RSA.verify (Just SHA384)
        rsaVerify HashSHA512 = RSA.verify (Just SHA512)

verifyECDSA :: HashALG -> PubKeyEC -> Maybe (ByteString -> ByteString -> Bool)
verifyECDSA hashALG key =
    case key of
        PubKeyEC_Named curveName pub -> verifyCurve curveName pub
        PubKeyEC_Prime {}            ->
            case find matchPrimeCurve $ enumFrom $ toEnum 0 of
                Nothing        -> Nothing
                Just curveName -> verifyCurve curveName (pubkeyEC_pub key)
  where
        matchPrimeCurve c =
            case ECC.getCurveByName c of
                ECC.CurveFP (ECC.CurvePrime p cc) ->
                    ECC.ecc_a cc == pubkeyEC_a key     &&
                    ECC.ecc_b cc == pubkeyEC_b key     &&
                    ECC.ecc_n cc == pubkeyEC_order key &&
                    p            == pubkeyEC_prime key
                _                                 -> False

        verifyCurve curveName pub = Just $ \msg sigBS ->
            case decodeASN1' BER sigBS of
                Left _ -> False
                Right [Start Sequence,IntVal r,IntVal s,End Sequence] ->
                    case unserializePoint (ECC.getCurveByName curveName) pub of
                        Nothing     -> False
                        Just pubkey -> (ecdsaVerify hashALG) pubkey (ECDSA.Signature r s) msg
                Right _ -> False

        unserializePoint curve (SerializedPoint bs) =
            case B.uncons bs of
                Nothing                -> Nothing
                Just (ptFormat, input) ->
                    case ptFormat of
                        4 -> if B.length bs == 2 * bytes
                                then Nothing
                                else
                                    let (x, y) = B.splitAt bytes input
                                        p      = ECC.Point (os2ip x) (os2ip y)
                                     in if ECC.isPointValid curve p
                                            then Just $ ECDSA.PublicKey curve p
                                            else Nothing
                        -- 2 and 3 for compressed format.
                        _ -> Nothing
          where bits  = numBits . ECC.ecc_n . ECC.common_curve $ curve
                bytes = (bits + 7) `div` 8

        ecdsaVerify HashMD2    = ECDSA.verify MD2
        ecdsaVerify HashMD5    = ECDSA.verify MD5
        ecdsaVerify HashSHA1   = ECDSA.verify SHA1
        ecdsaVerify HashSHA224 = ECDSA.verify SHA224
        ecdsaVerify HashSHA256 = ECDSA.verify SHA256
        ecdsaVerify HashSHA384 = ECDSA.verify SHA384
        ecdsaVerify HashSHA512 = ECDSA.verify SHA512
