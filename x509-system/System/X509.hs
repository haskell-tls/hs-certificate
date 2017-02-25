{-# LANGUAGE CPP #-}
-- |
-- Module      : System.X509
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : good
--
module System.X509
    ( getSystemCertificateStore
    ) where

#if defined(WINDOWS)
import System.X509.Win32
#elif defined(MACOSX)
import System.X509.MacOS
#else
import System.X509.Unix
#endif
