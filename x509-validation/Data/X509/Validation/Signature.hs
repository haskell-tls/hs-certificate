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
    ( verifyCertificateSignature
    , verifySignature
    , SignatureVerification(..)
    ) where

import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.Hash.SHA1 as SHA1
import Crypto.PubKey.HashDescr

import Data.ByteString (ByteString)
import Data.X509

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

-- | Verify a SignedCertificate against a specified public key
verifyCertificateSignature :: SignedCertificate -> PubKey -> SignatureVerification
verifyCertificateSignature signedCert pubKey =
    verifySignature (signedAlg signed)
                    pubKey
                    (getSignedData signedCert)
                    (signedSignature signed)
  where signed = getSigned signedCert

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

        hashDescr          = toDescr hashALG

        verifyF (PubKeyRSA key) = Just $ RSA.verify hashDescr key
        verifyF (PubKeyDSA key)
            | hashALG == HashSHA1 && False = Just $ \a -> DSA.verify SHA1.hash key (dsaToSignature a)
            | otherwise           = Nothing
        verifyF _ = Nothing

        -- TODO : need to work out how to get R/S from the bytestring
        dsaToSignature _ = (0,0)
