-- |
-- Module      : Data.X509.Memory
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
--
module Data.X509.Memory
    ( readKeyFileFromMemory
    , readSignedObjectFromMemory
    ) where

import Data.ASN1.Types
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.Maybe
import qualified Data.X509 as X509
import Data.PEM (pemParseBS, pemContent, pemName, PEM)
import qualified Data.ByteString as B
import qualified Crypto.Types.PubKey.DSA as DSA

readKeyFileFromMemory :: B.ByteString -> [X509.PrivKey]
readKeyFileFromMemory = either (const []) (catMaybes . foldl pemToKey []) . pemParseBS
  where pemToKey acc pem =
            case decodeASN1' BER (pemContent pem) of
                Left _     -> acc
                Right asn1 -> case pemName pem of
                                "PRIVATE KEY" ->
                                    tryRSA asn1 : tryDSA asn1 : acc
                                "RSA PRIVATE KEY" ->
                                    tryRSA asn1 : acc
                                "DSA PRIVATE KEY" ->
                                    tryDSA asn1 : acc
                                _                 -> acc
        tryRSA asn1 = case fromASN1 asn1 of
                    Left _      -> Nothing
                    Right (k,_) -> Just $ X509.PrivKeyRSA k
        tryDSA asn1 = case fromASN1 asn1 of
                    Left _      -> Nothing
                    Right (k,_) -> Just $ X509.PrivKeyDSA $ DSA.toPrivateKey k

readSignedObjectFromMemory :: (ASN1Object a, Eq a, Show a)
                           => B.ByteString
                           -> [X509.SignedExact a]
readSignedObjectFromMemory = either (const []) (foldl pemToSigned []) . pemParseBS
  where pemToSigned acc pem =
            case X509.decodeSignedObject $ pemContent pem of
                Left _    -> acc
                Right obj -> obj : acc
