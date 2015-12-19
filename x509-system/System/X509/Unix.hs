-- |
-- Module      : System.X509
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
module System.X509.Unix
    ( getSystemCertificateStore
    ) where

import System.Directory (getDirectoryContents, doesFileExist, doesDirectoryExist)
import System.Environment (getEnv)
import System.FilePath ((</>))

import Data.List (isPrefixOf)
import Data.PEM (PEM(..), pemParseBS)
import Data.Either
import qualified Data.ByteString as B
import Data.X509
import Data.X509.CertificateStore

import Control.Applicative ((<$>))
import Control.Monad (filterM)
import qualified Control.Exception as E

import Data.Char
import Data.Maybe (catMaybes)
import Data.Monoid (mconcat)

defaultSystemPaths :: [FilePath]
defaultSystemPaths =
    [ "/etc/ssl/certs/"                 -- linux
    , "/system/etc/security/cacerts/"   -- android
    , "/usr/local/share/certs/"         -- freebsd
    , "/etc/ssl/cert.pem"               -- openbsd
    ]

envPathOverride :: String
envPathOverride = "SYSTEM_CERTIFICATE_PATH"

-- List all the path susceptible to contains a certificate in a directory
--
-- if the parameter is not a directory, hilarity follows.
listDirectoryCerts :: FilePath -> IO [FilePath]
listDirectoryCerts path =
    getDirContents >>= filterM doesFileExist
  where
    isHashedFile s = length s == 10
                  && isDigit (s !! 9)
                  && (s !! 8) == '.'
                  && all isHexDigit (take 8 s)
    isCert x = (not $ isPrefixOf "." x) && (not $ isHashedFile x)

    getDirContents = E.catch (map (path </>) . filter isCert <$> getDirectoryContents path) emptyPaths
            where emptyPaths :: E.IOException -> IO [FilePath]
                  emptyPaths _ = return []

makeCertStore :: FilePath -> IO (Maybe CertificateStore)
makeCertStore path = do
    isDir  <- doesDirectoryExist path
    isFile <- doesFileExist path
    wrapStore <$> (if isDir then makeDirStore else if isFile then makeFileStore else return [])
  where
    wrapStore :: [SignedCertificate] -> Maybe CertificateStore
    wrapStore [] = Nothing
    wrapStore l  = Just $ makeCertificateStore l

    makeFileStore = readCertificates path
    makeDirStore  = do
        certFiles <- listDirectoryCerts path
        concat <$> mapM readCertificates certFiles


getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore = mconcat . catMaybes <$> (getSystemPaths >>= mapM makeCertStore)

getSystemPaths :: IO [FilePath]
getSystemPaths = E.catch ((:[]) <$> getEnv envPathOverride) inDefault
    where
        inDefault :: E.IOException -> IO [FilePath]
        inDefault _ = return defaultSystemPaths

-- Try to read certificate from the content of a file.
--
-- The file may contains multiple certificates
readCertificates :: FilePath -> IO [SignedCertificate]
readCertificates file = E.catch (either (const []) (rights . map getCert) . pemParseBS <$> B.readFile file) skipIOError
    where
        getCert = decodeSignedCertificate . pemContent
        skipIOError :: E.IOException -> IO [SignedCertificate]
        skipIOError _ = return []
