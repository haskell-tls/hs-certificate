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
    , Extensions(..)
    ) where

import Control.Applicative
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.X509.Internal

-- | An undecoded extension
data ExtensionRaw = ExtensionRaw
    { extRawOID      :: OID    -- ^ OID of this extension
    , extRawCritical :: {-# UNPACK #-} !Bool   -- ^ if this extension is critical
    , extRawASN1     :: [ASN1] -- ^ the associated ASN1
    } deriving (Show,Eq)

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
            Boolean b:OctetString obj:End Sequence:xs2 -> extractExt b obj xs2
            OctetString obj:End Sequence:xs2           -> extractExt False obj xs2
            _                                          -> Left ("fromASN1: X509.ExtensionRaw: unknown format:" ++ show xs)
      where
        extractExt critical bs remainingStream =
            case decodeASN1' BER bs of
                Left err -> Left ("fromASN1: X509.ExtensionRaw: OID=" ++ show oid ++
                                  ": cannot decode data: " ++ show err)
                Right r  -> Right (ExtensionRaw oid critical r, remainingStream)
    fromASN1 l                                      =
        Left ("fromASN1: X509.ExtensionRaw: unknown format:" ++ show l)

encodeExt :: ExtensionRaw -> [ASN1]
encodeExt (ExtensionRaw oid critical asn1) =
    let bs = encodeASN1' DER asn1
     in asn1Container Sequence ([OID oid] ++ (if critical then [Boolean True] else []) ++ [OctetString bs])
