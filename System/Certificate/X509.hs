{-# LANGUAGE CPP #-}
-- |
-- Module      : System.Certificate.X509
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : good
--
module System.Certificate.X509
	( getSystemCertificateStore
	) where

#if defined(WINDOWS)
import System.Certificate.X509.Win32
#elif defined(MACOSX)
import System.Certificate.X509.MacOS
#else
import System.Certificate.X509.Unix
#endif
