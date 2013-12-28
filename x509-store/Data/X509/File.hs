module Data.X509.File
    ( readSignedObject
    , readKeyFile
    ) where

import Control.Applicative
import Data.ASN1.Types
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.Maybe
import qualified Data.X509 as X509
import Data.PEM (pemParseLBS, pemContent, pemName, PEM)
import qualified Data.ByteString.Lazy as L
import qualified Crypto.Types.PubKey.DSA as DSA

readPEMs :: FilePath -> IO [PEM]
readPEMs filepath = do
    content <- L.readFile filepath
    return $ either error id $ pemParseLBS content

-- | return all the signed objects in a file.
--
-- (only one type at a time).
readSignedObject :: (ASN1Object a, Eq a, Show a)
                 => FilePath
                 -> IO [X509.SignedExact a]
readSignedObject filepath = foldl pemToSigned [] <$> readPEMs filepath
  where pemToSigned acc pem =
            case X509.decodeSignedObject $ pemContent pem of
                Left _    -> acc
                Right obj -> obj : acc

-- | return all the public key that were successfully read from a file.
readKeyFile :: FilePath -> IO [X509.PrivKey]
readKeyFile path = catMaybes . foldl pemToKey [] <$> readPEMs path
  where pemToKey acc pem = do
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
