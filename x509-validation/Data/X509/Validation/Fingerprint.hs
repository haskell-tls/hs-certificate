-- |
-- Module      : Data.X509.Validation.Fingerprint
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Data.X509.Validation.Fingerprint
    ( getFingerprint
    , toDescr
    ) where

import Crypto.PubKey.HashDescr
import Data.X509
import Data.ASN1.Types
import Data.ByteString (ByteString)

-- | Get the fingerprint of the whole signed object
-- using the hashing algorithm specified
getFingerprint :: (Show a, Eq a, ASN1Object a)
               => SignedExact a -- ^ object to fingerprint
               -> HashALG       -- ^ algorithm to compute the fingerprint
               -> ByteString    -- ^ fingerprint in binary form
getFingerprint sobj halg = hashF $ encodeSignedObject sobj
  where hashDescr = toDescr halg
        hashF     = hashFunction hashDescr

-- | Convert a hash algorithm into a Hash Description
toDescr :: HashALG -> HashDescr
toDescr HashMD2    = hashDescrMD2
toDescr HashMD5    = hashDescrMD5
toDescr HashSHA1   = hashDescrSHA1
toDescr HashSHA224 = hashDescrSHA224
toDescr HashSHA256 = hashDescrSHA256
toDescr HashSHA384 = hashDescrSHA384
toDescr HashSHA512 = hashDescrSHA512
