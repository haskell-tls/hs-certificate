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
    ) where

import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.Hash.SHA1 as SHA1
import Crypto.PubKey.HashDescr

import Data.ByteString (ByteString)
import Data.X509
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding

-- | A set of possible return from signature verification.
--
-- Only SignaturePass should be accepted as success.
--
-- Other values are only useful to differentiate the failure
-- reason, but are all equivalent to failure.
--
data SignatureVerification =
      SignaturePass           -- ^ verification succeeded
    | SignatureFailed         -- ^ verification failed
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
verifySignature (SignatureALG_Unknown _) _ _ _ = SignatureUnimplemented
verifySignature (SignatureALG hashALG pubkeyALG) pubkey cdata signature
    | pubkeyToAlg pubkey == pubkeyALG = case verifyF pubkey of
                                            Nothing -> SignatureUnimplemented
                                            Just f  -> if f cdata signature
                                                            then SignaturePass
                                                            else SignatureFailed
    | otherwise                       = SignaturePubkeyMismatch
  where
        toDescr HashMD2    = hashDescrMD2
        toDescr HashMD5    = hashDescrMD5
        toDescr HashSHA1   = hashDescrSHA1
        toDescr HashSHA224 = hashDescrSHA224
        toDescr HashSHA256 = hashDescrSHA256
        toDescr HashSHA384 = hashDescrSHA384
        toDescr HashSHA512 = hashDescrSHA512

        verifyF (PubKeyRSA key) = Just $ RSA.verify (toDescr hashALG) key
        verifyF (PubKeyDSA key)
            | hashALG == HashSHA1 = Just $ \a b -> case dsaToSignature a of
                                                    Nothing     -> False
                                                    Just dsaSig -> DSA.verify SHA1.hash key dsaSig b
            | otherwise           = Nothing
        verifyF _ = Nothing

        dsaToSignature :: ByteString -> Maybe DSA.Signature
        dsaToSignature b =
            case decodeASN1' BER b of
                Left _     -> Nothing
                Right asn1 -> case fromASN1 asn1 of
                                Left _            -> Nothing
                                Right (dsaSig, _) -> Just dsaSig
