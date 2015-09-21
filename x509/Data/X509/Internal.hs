-- |
-- Module      : Data.X509.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE CPP #-}
module Data.X509.Internal
    ( module Data.ASN1.Parse
    , asn1Container
    , OID
    -- * error handling
    , ErrT
    , runErrT
    ) where

import Data.ASN1.Types
import Data.ASN1.Parse

#if MIN_VERSION_mtl(2,2,1)
import Control.Monad.Except
runErrT :: ExceptT e m a -> m (Either e a)
runErrT = runExceptT
type ErrT = ExceptT
#else
import Control.Monad.Error
runErrT :: ErrorT e m a -> m (Either e a)
runErrT = runErrorT
type ErrT = ErrorT
#endif

-- | create a container around the stream of ASN1
asn1Container :: ASN1ConstructionType -> [ASN1] -> [ASN1]
asn1Container ty l = [Start ty] ++ l ++ [End ty]
