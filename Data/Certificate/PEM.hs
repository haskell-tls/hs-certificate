-- |
-- Module      : Data.Certificate.PEM
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Read PEM files
--
module Data.Certificate.PEM (
	parsePEM,
	parsePEMCert,
	parsePEMKey
	) where

import qualified Codec.Binary.Base64 as Base64
import qualified Data.ByteString.Lazy as L
import Data.Either

packChar :: String -> L.ByteString
packChar = L.pack . map (toEnum.fromEnum)

base64decode :: L.ByteString -> Either String L.ByteString
base64decode s =
	case Base64.decode $ map (toEnum . fromEnum) $ L.unpack s of
		Nothing -> Left ("base64 decode failed : " ++ show s)
		Just ds -> Right $ L.pack ds

mapTill :: (a -> Bool) -> (a -> b) -> [a] -> [b]
mapTill _    _ []     = []
mapTill endp f (x:xs) = if endp x then [] else f x : mapTill endp f xs

{- | parse a PEM content that is delimited by the begin string and the end string,
   and returns the base64-decoded bytestring on success or a string on error. -}
parsePEM :: String -> String -> L.ByteString -> Either String L.ByteString
parsePEM begin end content =
	concatErrOrContent $ mapTill ((==) pend) (base64decode) $ tail $ dropWhile ((/=) pbegin) ls
	where
		ls     = L.split (toEnum $ fromEnum '\n') content
		pbegin = packChar begin
		pend   = packChar end
		concatErrOrContent x =
			let (l, r) = partitionEithers x in
			if l == [] then Right $ L.concat r else Left $ head l

parsePEMCert :: L.ByteString -> Either String L.ByteString
parsePEMCert = parsePEM "-----BEGIN CERTIFICATE-----" "-----END CERTIFICATE-----"

parsePEMKey :: L.ByteString -> Either String L.ByteString
parsePEMKey = parsePEM "-----BEGIN RSA PRIVATE KEY-----" "-----END RSA PRIVATE KEY-----"
