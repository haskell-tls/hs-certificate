-- |
-- Module      : Data.X509.Signed
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Exposes helpers for X509 certificate and revocation list, signed structures.
--
-- Signed structures are of the form:
--      Sequence {
--          object              a
--          signatureAlgorithm  AlgorithmIdentifier
--          signatureValue      BitString
--      }
--
-- Unfortunately as lots of signed objects published have been signed on an
-- arbitrary BER ASN1 encoding (instead of using the unique DER encoding) or in
-- a non-valid DER implementation, we need to keep the raw data being signed,
-- as we can't recompute the bytestring used to sign for non compliant cases.
--
-- Signed represent the pure data type for compliant cases, and SignedExact
-- the real world situation of having to deal with compliant and non-compliant cases.
--
module Data.X509.Signed
    (
    -- * Types
      Signed(..)
    , SignedExact
    -- * SignedExact to Signed
    , getSigned
    -- * Object to Signed and SignedExact
    , objectToSignedExact
    , objectToSigned
    ) where

import Control.Arrow (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.X509.AlgorithmIdentifier
import Data.ASN1.Types

-- | Represent a signed object using a traditional X509 structure.
--
-- When dealing with external certificate, use the SignedExact structure
-- not this one.
data (Eq a, ASN1Object a) => Signed a = Signed
    { signedObject    :: a            -- ^ Object to sign
    , signedAlg       :: SignatureALG -- ^ Signature Algorithm used
    , signedSignature :: B.ByteString -- ^ Signature as bytes
    } deriving (Eq)

-- | Represent the signed object plus the raw data that we need to
-- keep around for non compliant case to be able to verify signature.
data (Eq a, ASN1Object a) => SignedExact a = SignedExact
    { getSigned      :: Signed a     -- ^ get the decoded Signed data
    , exactObjectRaw :: B.ByteString -- ^ The raw representation of the object a
                                     -- TODO: in later version, replace with offset in exactRaw
    , exactRaw       :: B.ByteString -- ^ The raw representation of the whole signed structure
    }

-- | make a 'SignedExact' copy of a 'Signed' object
signedToExact :: Signed a -> SignedExact a
signedToExact signed = undefined

-- | Transform an object into a 'SignedExact' object
objectToSignedExact :: (Eq a, ASN1Object a)
                    => (ByteString -> (ByteString, r)) -- ^ signature function
                    -> a                               -- ^ object to encode
                    -> (SignedExact a, r)
objectToSignedExact signatureFunction object = undefined

-- | Transform an object into a 'Signed' object.
objectToSigned :: (Eq a, ASN1Object a) => (ByteString -> (ByteString, r)) -> a -> (Signed a, r)
objectToSigned signatureFunction object = first getSigned $ objectToSignedExact signatureFunction object
