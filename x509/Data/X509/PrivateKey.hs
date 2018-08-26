-- |
-- Module      : Data.X509.PublicKey
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Private key handling in X.509 infrastructure
--
module Data.X509.PrivateKey
    ( PrivKey(..)
    , PrivKeyEC(..)
    , privkeyToAlg
    ) where

import Data.X509.AlgorithmIdentifier
import Data.X509.PublicKey (SerializedPoint(..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448   as X448
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.Ed448      as Ed448

-- | Elliptic Curve Private Key
--
-- TODO: missing support for binary curve.
data PrivKeyEC =
      PrivKeyEC_Prime
        { privkeyEC_priv      :: Integer
        , privkeyEC_a         :: Integer
        , privkeyEC_b         :: Integer
        , privkeyEC_prime     :: Integer
        , privkeyEC_generator :: SerializedPoint
        , privkeyEC_order     :: Integer
        , privkeyEC_cofactor  :: Integer
        , privkeyEC_seed      :: Integer
        }
    | PrivKeyEC_Named
        { privkeyEC_name      :: ECC.CurveName
        , privkeyEC_priv      :: Integer
        }
    deriving (Show,Eq)

-- | Private key types known and used in X.509
data PrivKey =
      PrivKeyRSA RSA.PrivateKey -- ^ RSA private key
    | PrivKeyDSA DSA.PrivateKey -- ^ DSA private key
    | PrivKeyEC  PrivKeyEC      -- ^ EC private key
    | PrivKeyX25519 X25519.SecretKey   -- ^ X25519 private key
    | PrivKeyX448 X448.SecretKey       -- ^ X448 private key
    | PrivKeyEd25519 Ed25519.SecretKey -- ^ Ed25519 private key
    | PrivKeyEd448 Ed448.SecretKey     -- ^ Ed448 private key
    deriving (Show,Eq)

-- | Convert a Private key to the Public Key Algorithm type
privkeyToAlg :: PrivKey -> PubKeyALG
privkeyToAlg (PrivKeyRSA _)         = PubKeyALG_RSA
privkeyToAlg (PrivKeyDSA _)         = PubKeyALG_DSA
privkeyToAlg (PrivKeyEC _)          = PubKeyALG_EC
privkeyToAlg (PrivKeyX25519 _)      = PubKeyALG_X25519
privkeyToAlg (PrivKeyX448 _)        = PubKeyALG_X448
privkeyToAlg (PrivKeyEd25519 _)     = PubKeyALG_Ed25519
privkeyToAlg (PrivKeyEd448 _)       = PubKeyALG_Ed448

