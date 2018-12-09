-- |
-- Module      : Data.X509.Validation.Fingerprint
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Data.X509.Validation.Fingerprint
    ( Fingerprint(..)
    , getFingerprint
    ) where

import Crypto.Hash
import Data.X509
import Data.ASN1.Types
import Data.ByteArray (convert, ByteArrayAccess)
import Data.ByteString (ByteString)

-- | Fingerprint of a certificate
newtype Fingerprint = Fingerprint ByteString
    deriving (Show,Eq,ByteArrayAccess)

-- | Get the fingerprint of the whole signed object
-- using the hashing algorithm specified
getFingerprint :: (Show a, Eq a, ASN1Object a)
               => SignedExact a -- ^ object to fingerprint
               -> HashALG       -- ^ algorithm to compute the fingerprint
               -> Fingerprint   -- ^ fingerprint in binary form
getFingerprint sobj halg = Fingerprint $ mkHash halg $ encodeSignedObject sobj
  where
    mkHash HashMD2    = convert . hashWith MD2
    mkHash HashMD5    = convert . hashWith MD5
    mkHash HashSHA1   = convert . hashWith SHA1
    mkHash HashSHA224 = convert . hashWith SHA224
    mkHash HashSHA256 = convert . hashWith SHA256
    mkHash HashSHA384 = convert . hashWith SHA384
    mkHash HashSHA512 = convert . hashWith SHA512
