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
    ( getSystemCertificateStore
    ) where

import System.Directory (getDirectoryContents, doesFileExist)
import System.Environment (getEnv)
import System.FilePath ((</>))

import Data.List (isPrefixOf)
import Data.PEM (PEM(..), pemParseBS)
import Data.Either
import Data.Certificate.X509
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.CertificateStore

import Control.Applicative ((<$>))
import Control.Monad (filterM)
import qualified Control.Exception as E

import Data.Char

defaultSystemPath :: FilePath
defaultSystemPath = "/etc/ssl/certs/"

envPathOverride :: String
envPathOverride = "SYSTEM_CERTIFICATE_PATH"

listDirectoryCerts :: FilePath -> IO [FilePath]
listDirectoryCerts path = (map (path </>) . filter isCert <$> getDirectoryContents path)
                      >>= filterM doesFileExist
    where isHashedFile s = length s == 10
                        && isDigit (s !! 9)
                        && (s !! 8) == '.'
                        && all isHexDigit (take 8 s)
          isCert x = (not $ isPrefixOf "." x) && (not $ isHashedFile x)

getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore = makeCertificateStore . concat <$> (getSystemPath >>= listDirectoryCerts >>= mapM readCertificates)

getSystemPath :: IO FilePath
getSystemPath = E.catch (getEnv envPathOverride) inDefault
    where
        inDefault :: E.IOException -> IO FilePath
        inDefault _ = return defaultSystemPath

readCertificates :: FilePath -> IO [X509]
readCertificates file = E.catch (either (const []) (rights . map getCert) . pemParseBS <$> B.readFile file) skipIOError
    where
        getCert pem = decodeCertificate $ L.fromChunks [pemContent pem]
        skipIOError :: E.IOException -> IO [X509]
        skipIOError _ = return []
