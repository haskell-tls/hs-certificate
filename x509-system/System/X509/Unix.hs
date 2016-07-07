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

import System.Environment (getEnv)
import Data.X509.CertificateStore

import Control.Applicative ((<$>))
import qualified Control.Exception as E

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

getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore = mconcat . catMaybes <$> (getSystemPaths >>= mapM readCertificateStore)

getSystemPaths :: IO [FilePath]
getSystemPaths = E.catch ((:[]) <$> getEnv envPathOverride) inDefault
    where
        inDefault :: E.IOException -> IO [FilePath]
        inDefault _ = return defaultSystemPaths
