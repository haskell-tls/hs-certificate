module Data.X509.File
    ( readSignedObject
    , readKeyFile
    ) where

import Control.Applicative
import Data.ASN1.Types
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import qualified Data.X509 as X509
import Data.PEM (pemParseLBS, pemContent, pemName)
import qualified Data.ByteString.Lazy as L

readPEMFile file = do
    content <- L.readFile file
    return $ either error id $ pemParseLBS content

-- | return all the 
readSignedObject file = do
    content <- L.readFile file
    return $ either error (map (X509.decodeSignedObject . pemContent)) $ pemParseLBS content

-- | return all the public key that were successfully read from a file.
readKeyFile :: FilePath -> IO [X509.PrivKey]
readKeyFile path = foldl pemToKey [] <$> readPEMFile path
  where pemToKey acc pem = do
            case decodeASN1' BER (pemContent pem) of
                Left _     -> acc
                Right asn1 -> case pemName pem of
                                "RSA PRIVATE KEY" ->
                                    case fromASN1 asn1 of
                                        Left err    -> acc
                                        Right (k,_) -> X509.PrivKeyRSA k : acc
                                "DSA PRIVATE KEY" ->
                                    case fromASN1 asn1 of
                                        Left err    -> acc 
                                        Right (k,_) -> X509.PrivKeyDSA k : acc
                                _                 -> acc
