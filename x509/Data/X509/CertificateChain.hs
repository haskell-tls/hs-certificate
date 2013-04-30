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
import Data.X509.Signed (SignedExact)
import Data.ByteString (ByteString)

-- | A chain of X.509 certificates in exact form.
newtype CertificateChain = CertificateChain [SignedExact Certificate]

-- | Represent a chain of X.509 certificates in bytestring form.
newtype CertificateChainRaw = CertificateChainRaw [ByteString]

decodeCertificateChain :: CertificateChainRaw -> Either String CertificateChain
decodeCertificateChain (CertificateChainRaw l) =
    undefined

encodeCertificateChain :: CertificateChain -> CertificateChainRaw
encodeCertificateChain chain = undefined
