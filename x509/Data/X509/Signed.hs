-- |
-- Module      : Data.X509.Signed
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Exposes helpers for X509 certificate and revocation list, signed structures.
--
-- Signed structures are of the form:
--      Sequence {
--          object              a
--          signatureAlgorithm  AlgorithmIdentifier
--          signatureValue      BitString    
--      }
--
--
module Data.X509.Signed
    (
    ) where

import qualified Data.ByteString as B
import Data.X509.Internal
import Data.X509.AlgorithmIdentifier

data Signed a = Signed
    { signedObject       :: a
    , signedSignatureALG :: SignatureALG
    , signedSignature    :: B.ByteString
    } deriving (Show)
