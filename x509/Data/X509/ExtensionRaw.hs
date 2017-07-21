-- |
-- Module      : Data.X509.ExtensionRaw
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- extension marshalling
--
module Data.X509.ExtensionRaw
    ( ExtensionRaw(..)
    , tryExtRawASN1
    , extRawASN1
    , Extensions(..)
    ) where

import Control.Applicative
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.X509.Internal
import qualified Data.ByteString as B

-- | An undecoded extension
data ExtensionRaw = ExtensionRaw
    { extRawOID      :: OID    -- ^ OID of this extension
    , extRawCritical :: Bool   -- ^ if this extension is critical
    , extRawContent  :: B.ByteString -- ^ undecoded content
    } deriving (Show,Eq)

tryExtRawASN1 :: ExtensionRaw -> Either String [ASN1]
tryExtRawASN1 (ExtensionRaw oid _ content) =
    case decodeASN1' BER content of
        Left err -> Left $ "fromASN1: X509.ExtensionRaw: OID=" ++ show oid ++ ": cannot decode data: " ++ show err
        Right r  -> Right r

extRawASN1 :: ExtensionRaw -> [ASN1]
extRawASN1 extRaw = either error id $ tryExtRawASN1 extRaw
{-# DEPRECATED extRawASN1 "use tryExtRawASN1 instead" #-}

-- | a Set of 'ExtensionRaw'
newtype Extensions = Extensions (Maybe [ExtensionRaw])
    deriving (Show,Eq)

instance ASN1Object Extensions where
    toASN1 (Extensions Nothing) = \xs -> xs
    toASN1 (Extensions (Just exts)) = \xs ->
        asn1Container (Container Context 3) (asn1Container Sequence (concatMap encodeExt exts)) ++ xs
    fromASN1 s = runParseASN1State (Extensions <$> parseExtensions) s
      where parseExtensions = onNextContainerMaybe (Container Context 3) $
                              onNextContainer Sequence (getMany getObject)

instance ASN1Object ExtensionRaw where
    toASN1 extraw = \xs -> encodeExt extraw ++ xs
    fromASN1 (Start Sequence:OID oid:xs) =
        case xs of
            Boolean b:OctetString obj:End Sequence:xs2 -> Right (ExtensionRaw oid b obj, xs2)
            OctetString obj:End Sequence:xs2           -> Right (ExtensionRaw oid False obj, xs2)
            _                                          -> Left ("fromASN1: X509.ExtensionRaw: unknown format:" ++ show xs)
    fromASN1 l                                      =
        Left ("fromASN1: X509.ExtensionRaw: unknown format:" ++ show l)

encodeExt :: ExtensionRaw -> [ASN1]
encodeExt (ExtensionRaw oid critical content) =
    asn1Container Sequence ([OID oid] ++ (if critical then [Boolean True] else []) ++ [OctetString content])
