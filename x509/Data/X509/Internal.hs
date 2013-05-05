-- |
-- Module      : Data.X509.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Data.X509.Internal
    ( module Data.ASN1.Parse
    , asn1Container
    , OID
    ) where

import Data.ASN1.Types
import Data.ASN1.Parse

-- | create a container around the stream of ASN1
asn1Container :: ASN1ConstructionType -> [ASN1] -> [ASN1]
asn1Container ty l = [Start ty] ++ l ++ [End ty]
