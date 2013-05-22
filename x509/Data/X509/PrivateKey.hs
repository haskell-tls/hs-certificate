-- |
-- Module      : Data.X509.PublicKey
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Public key handling in X.509 infrastructure
--
module Data.X509.PrivateKey
    ( PrivKey(..)
    , privkeyToAlg
    ) where

import Data.X509.AlgorithmIdentifier
import qualified Crypto.Types.PubKey.RSA as RSA
import qualified Crypto.Types.PubKey.DSA as DSA

-- | Private key types known and used in X.509
data PrivKey =
      PrivKeyRSA RSA.PrivateKey -- ^ RSA private key
    | PrivKeyDSA DSA.PrivateKey -- ^ DSA private key
    deriving (Show,Eq)

-- | Convert a Public key to the Public Key Algorithm type
privkeyToAlg :: PrivKey -> PubKeyALG
privkeyToAlg (PrivKeyRSA _)         = PubKeyALG_RSA
privkeyToAlg (PrivKeyDSA _)         = PubKeyALG_DSA
