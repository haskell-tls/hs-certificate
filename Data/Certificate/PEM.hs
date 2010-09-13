{-# LANGUAGE OverloadedStrings #-}

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
	parsePEMCert,
	parsePEMCertReq,
	parsePEMKey
	) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.ByteString.Base64
import Data.Either

mapTill :: (a -> Bool) -> (a -> b) -> [a] -> [b]
mapTill _    _ []     = []
mapTill endp f (x:xs) = if endp x then [] else f x : mapTill endp f xs

{- | parse a PEM content that is delimited by the begin string and the end string,
   and returns the base64-decoded bytestring on success or a string on error. -}
parsePEMSpecific :: ByteString -> ByteString -> ByteString -> Either String ByteString
parsePEMSpecific begin end content =
	concatErrOrContent $ mapTill ((==) end) (decode) $ tail $ dropWhile ((/=) begin) ls
	where
		ls     = BC.split '\n' content
		concatErrOrContent x =
			let (l, r) = partitionEithers x in
			if l == [] then Right $ B.concat r else Left $ head l

parsePEMCert :: ByteString -> Either String ByteString
parsePEMCert = parsePEMSpecific "-----BEGIN CERTIFICATE-----" "-----END CERTIFICATE-----"

parsePEMCertReq :: ByteString -> Either String ByteString
parsePEMCertReq = parsePEMSpecific "-----BEGIN CERTIFICATE REQUEST-----" "-----END CERTIFICATE REQUEST-----"

parsePEMKey :: ByteString -> Either String ByteString
parsePEMKey = parsePEMSpecific "-----BEGIN RSA PRIVATE KEY-----" "-----END RSA PRIVATE KEY-----"
