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
import Data.List (isPrefixOf, find)

import Data.PEM (PEM(..), pemParseBS)
import Data.Either
import Data.Certificate.X509
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

listSystemCertificates :: IO [FilePath]
listSystemCertificates = do
    path      <- getSystemPath
    map (path ++) . filter (not . isPrefixOf ".") <$> getDirectoryContents path

getSystemPath :: IO FilePath
getSystemPath = catch (getEnv envPathOverride) inDefault
    where
        inDefault :: IOException -> IO FilePath
        inDefault _ = return defaultSystemPath

readCertificates :: FilePath -> IO [X509]
readCertificates file = either (const []) (rights . map getCert) . pemParseBS <$> B.readFile file
    where getCert pem = decodeCertificate $ L.fromChunks [pemContent pem]

readAll :: IO [X509]
readAll = do
    certfiles <- listSystemCertificates
    concat . rights <$> mapM (trySE . readCertificates) certfiles

findCertificate :: (X509 -> Bool) -> IO (Maybe X509)
findCertificate f = find f <$> readAll

trySE :: IO a -> IO (Either SomeException a)
trySE = try
