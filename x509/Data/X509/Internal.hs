-- |
-- Module      : Data.X509.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE CPP #-}
module Data.X509.Internal
    ( module Data.ASN1.Parse
    , asn1Container
    , OID
    -- * error handling
    , ErrT
    , runErrT
    -- * IP <-> ByteString conversion
    , IP(..)
    , ipv4FromTuple
    , ipv6FromTuple
    , ipToBS
    , ipFromBS
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Lazy as BL
import qualified Foundation.Network.IPv4 as IPv4
import qualified Foundation.Network.IPv6 as IPv6
import Data.ASN1.Types
import Data.ASN1.Parse
import Data.Bits
import Data.Word
import Foundation.Network.IPv4(IPv4)
import Foundation.Network.IPv6(IPv6)

#if MIN_VERSION_mtl(2,2,1)
import Control.Monad.Except
runErrT :: ExceptT e m a -> m (Either e a)
runErrT = runExceptT
type ErrT = ExceptT
#else
import Control.Monad.Error
runErrT :: ErrorT e m a -> m (Either e a)
runErrT = runErrorT
type ErrT = ErrorT
#endif

-- | create a container around the stream of ASN1
asn1Container :: ASN1ConstructionType -> [ASN1] -> [ASN1]
asn1Container ty l = [Start ty] ++ l ++ [End ty]


-- | Unify both kind of IPs under one type
data IP
  = IPv6 IPv6
  | IPv4 IPv4
  deriving (Show, Eq, Ord)

-- | create an IPv6 from the given tuple
ipv6FromTuple :: (Word16, Word16, Word16, Word16, Word16, Word16, Word16, Word16) -> IP
ipv6FromTuple =
  IPv6 . IPv6.fromTuple

-- | decompose an IPv6 into a tuple
ipv4FromTuple :: (Word8, Word8, Word8, Word8) -> IP
ipv4FromTuple =
  IPv4 . IPv4.fromTuple

-- | Convert an 'IP' address to a 'ByteString'
ipToBS :: IP -> B.ByteString
ipToBS ip =
    case ip of
      IPv6 v6 -> ipv6ToBS v6
      IPv4 v4 -> ipv4ToBS v4
  where
    ipv4ToBS :: IPv4 -> B.ByteString
    ipv4ToBS v4 =
      let
        (a, b, c, d) = IPv4.toTuple v4
        x =  shiftL32 a 24
         .|. shiftL32 b 16
         .|. shiftL32 c 8
         .|. shiftL32 d 0
      in
        BL.toStrict $ B.toLazyByteString (B.word32BE x)
    ipv6ToBS :: IPv6 -> B.ByteString
    ipv6ToBS v6 =
      let
        (a, b, c, d, e, f, g, h) = IPv6.toTuple v6
        (x, y) =
          (  shiftL64 a 48
         .|. shiftL64 b 32
         .|. shiftL64 c 16
         .|. shiftL64 d 0
          ,  shiftL64 e 48
         .|. shiftL64 f 32
         .|. shiftL64 g 16
         .|. shiftL64 h 0
          )
      in
        BL.toStrict $ B.toLazyByteString (B.word64BE x <> B.word64BE y)

-- | Convert an encoded IP 'ByteString' back to an 'IP'
ipFromBS :: B.ByteString -> Either String IP
ipFromBS bytes =
    case B.length bytes of
      4  -> Right $ IPv4 $ ipv4FromBS bytes
      16 -> Right $ IPv6 $ ipv6FromBS bytes
      _  -> Left "IP from bytes: invalid bytes length"
  where
    ipv4FromBS :: B.ByteString -> IPv4
    ipv4FromBS bytes =
      let
        (a, b, c, d) =
          ( bytes `B.index` 0
          , bytes `B.index` 1
          , bytes `B.index` 2
          , bytes `B.index` 3
          )
      in
        IPv4.fromTuple (a, b, c, d)

    ipv6FromBS :: B.ByteString -> IPv6
    ipv6FromBS bytes =
      let
        (a, b, c, d, e, f, g, h) =
          ( (bytes `B.index` 0)  `shiftL16` 8 .|. (bytes `B.index` 1)  `shiftL16` 0
          , (bytes `B.index` 2)  `shiftL16` 8 .|. (bytes `B.index` 3)  `shiftL16` 0
          , (bytes `B.index` 4)  `shiftL16` 8 .|. (bytes `B.index` 5)  `shiftL16` 0
          , (bytes `B.index` 6)  `shiftL16` 8 .|. (bytes `B.index` 7)  `shiftL16` 0
          , (bytes `B.index` 8)  `shiftL16` 8 .|. (bytes `B.index` 9)  `shiftL16` 0
          , (bytes `B.index` 10) `shiftL16` 8 .|. (bytes `B.index` 11) `shiftL16` 0
          , (bytes `B.index` 12) `shiftL16` 8 .|. (bytes `B.index` 13) `shiftL16` 0
          , (bytes `B.index` 14) `shiftL16` 8 .|. (bytes `B.index` 15) `shiftL16` 0
          )
      in
        IPv6.fromTuple (a, b, c, d, e, f, g, h)


-- | Applied 'shiftL' with coercion from @Word8@ to @Word32@
shiftL32 :: Word8 -> Int -> Word32
shiftL32 x = shiftL (fromIntegral x)
infixl 8 `shiftL32`

-- | Applied 'shiftL' with coercion from @Word16@ to @Word64@
shiftL64 :: Word16 -> Int -> Word64
shiftL64 x = shiftL (fromIntegral x)
infixl 8 `shiftL64`

-- | Applied 'shiftL' on given byte from @ByteString@ with coercion from @Word8@ to @Word16@
shiftL16 :: Word8 -> Int -> Word16
shiftL16 x = shiftL (fromIntegral x)
infixl 8 `shiftL16`
