-- |
-- Module      : System.Certificate.X509
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unix only
--
-- this module is portable to unix system where there is usually
-- a /etc/ssl/certs with system X509 certificates.
--
-- the path can be dynamically override using the environment variable
-- defined by envPathOverride in the module, which by
-- default is SYSTEM_CERTIFICATE_PATH
--
module System.Certificate.X509.Unix
	( getSystemPath
	, readAll
	, findCertificate
	) where

import System.Directory (getDirectoryContents)
import System.Environment (getEnv)
import Data.List (isPrefixOf)

import Data.Either
import Data.Certificate.X509
import Data.Certificate.PEM
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Control.Applicative ((<$>))
import Control.Exception
import Control.Monad

import Prelude hiding (catch)

defaultSystemPath :: FilePath
defaultSystemPath = "/etc/ssl/certs/"

envPathOverride :: String
envPathOverride = "SYSTEM_CERTIFICATE_PATH"

getSystemPath :: IO FilePath
getSystemPath = catch (getEnv envPathOverride) inDefault
	where
		inDefault :: IOException -> IO FilePath
		inDefault _ = return defaultSystemPath

data ReadErr =
	  Exception IOException
	| CertError String
	deriving (Show,Eq)

readCertificate :: FilePath -> IO (Either ReadErr X509)
readCertificate file = do
	rawdata <- try $ B.readFile file :: IO (Either IOException B.ByteString)
	either (return . Left . Exception) parseCert $ rawdata
	where
		parseCert pemdata = case parsePEMCert pemdata of
			Nothing       -> return $ Left $ CertError "certificate not in PEM format"
			Just certdata -> do
				return $ either (Left . CertError) Right $ decodeCertificate $ L.fromChunks [certdata]

readAll :: IO [Either ReadErr X509]
readAll = do
	path      <- getSystemPath
	certfiles <- filter (not . isPrefixOf ".") <$> getDirectoryContents path
	forM certfiles $ \certfile -> readCertificate (path ++ certfile)

findCertificate :: (X509 -> Bool) -> IO (Maybe X509)
findCertificate f = do
	path      <- getSystemPath
	certfiles <- filter (not . isPrefixOf ".") <$> getDirectoryContents path
	loop $ map (path ++) certfiles
	where
		loop []     = return Nothing
		loop (x:xs) = do
			ox509 <- readCertificate x
			case ox509 of
				Left _     -> loop xs
				Right x509 -> if f x509 then return $ Just x509 else loop xs
