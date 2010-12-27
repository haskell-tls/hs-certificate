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
module Data.Certificate.PEM
	( parsePEMCert
	, parsePEMCertReq
	, parsePEMKey
	, parsePEMKeyRSA
	, parsePEMKeyDSA
	, parsePEMs
	, findPEM
	) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.ByteString.Base64
import Data.List

type PEM = (String, ByteString)

takeTillEnd :: [ByteString] -> ([ByteString], [ByteString])
takeTillEnd ls = break (BC.isPrefixOf "-----END ") ls

findSectionName :: ByteString -> String
findSectionName s = BC.unpack $ B.take (B.length x - 5) x
	where x = B.drop 11 s

parsePEMSections :: [ByteString] -> [PEM]
parsePEMSections []     = []
parsePEMSections (x:xs)
	| "-----BEGIN " `B.isPrefixOf` x =
		let (content, rest) = takeTillEnd xs in
		case decode $ B.concat content of
			Left _  -> parsePEMSections rest
			Right y -> (findSectionName x, y) : parsePEMSections rest
	| otherwise                      = parsePEMSections xs

parsePEMs :: ByteString -> [PEM]
parsePEMs content = parsePEMSections $ BC.lines content

findPEM :: String -> [PEM] -> Maybe ByteString
findPEM name = maybe Nothing (Just . snd) . find ((==) name . fst)

parsePEMCert :: ByteString -> Maybe ByteString
parsePEMCert = findPEM "CERTIFICATE" . parsePEMs

parsePEMCertReq :: ByteString -> Maybe ByteString
parsePEMCertReq = findPEM "CERTIFICATE REQUEST" . parsePEMs

parsePEMKeyRSA :: ByteString -> Maybe ByteString
parsePEMKeyRSA = findPEM "RSA PRIVATE KEY" . parsePEMs

parsePEMKeyDSA :: ByteString -> Maybe ByteString
parsePEMKeyDSA = findPEM "DSA PRIVATE KEY" . parsePEMs

{-# DEPRECATED parsePEMKey "use parsePEMKeyRSA now" #-}
parsePEMKey :: ByteString -> Maybe ByteString
parsePEMKey = parsePEMKeyRSA
