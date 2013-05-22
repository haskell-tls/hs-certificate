-- |
-- Module      : Data.X509.CertificateChain
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Data.X509.CertificateChain
    ( CertificateChain(..)
    , CertificateChainRaw(..)
    -- * marshall between CertificateChain and CertificateChainRaw
    , decodeCertificateChain
    , encodeCertificateChain
    ) where

import Data.X509.Cert (Certificate)
import Data.X509.Signed (SignedExact, decodeSignedObject, encodeSignedObject)
import Data.ByteString (ByteString)

-- | A chain of X.509 certificates in exact form.
newtype CertificateChain = CertificateChain [SignedExact Certificate]
    deriving (Show,Eq)

-- | Represent a chain of X.509 certificates in bytestring form.
newtype CertificateChainRaw = CertificateChainRaw [ByteString]
    deriving (Show,Eq)

-- | Decode a CertificateChainRaw into a CertificateChain if every
-- raw certificate are decoded correctly, otherwise return the index of the
-- failed certificate and the error associated.
decodeCertificateChain :: CertificateChainRaw -> Either (Int, String) CertificateChain
decodeCertificateChain (CertificateChainRaw l) =
    either Left (Right . CertificateChain) $ loop 0 l
  where loop _ []     = Right []
        loop i (r:rs) = case decodeSignedObject r of
                         Left err -> Left (i, err)
                         Right o  -> either Left (Right . (o :)) $ loop (i+1) rs

-- | Convert a CertificateChain into a CertificateChainRaw
encodeCertificateChain :: CertificateChain -> CertificateChainRaw
encodeCertificateChain (CertificateChain chain) =
    CertificateChainRaw $ map encodeSignedObject chain
