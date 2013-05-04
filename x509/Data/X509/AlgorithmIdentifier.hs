-- |
-- Module      : Data.X509.AlgorithmIdentifier
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Data.X509.AlgorithmIdentifier
    ( HashALG(..)
    , PubKeyALG(..)
    , SignatureALG(..)
    ) where

import Data.ASN1.Types
import Data.List (find)

-- | Hash Algorithm
data HashALG =
      HashMD2
    | HashMD5
    | HashSHA1
    | HashSHA224
    | HashSHA256
    | HashSHA384
    | HashSHA512
    deriving (Show,Eq)

-- | Public Key Algorithm
data PubKeyALG =
      PubKeyALG_RSA         -- ^ RSA Public Key algorithm
    | PubKeyALG_DSA         -- ^ DSA Public Key algorithm
    | PubKeyALG_ECDSA       -- ^ ECDSA Public Key algorithm
    | PubKeyALG_DH          -- ^ Diffie Hellman Public Key algorithm
    | PubKeyALG_Unknown OID -- ^ Unknown Public Key algorithm
    deriving (Show,Eq)

-- | Signature Algorithm often composed of
-- a public key algorithm and a hash algorithm
data SignatureALG =
      SignatureALG HashALG PubKeyALG
    | SignatureALG_Unknown OID
    deriving (Show,Eq)

instance OIDable PubKeyALG where
    getObjectID PubKeyALG_RSA   = [1,2,840,113549,1,1,1]
    getObjectID PubKeyALG_DSA   = [1,2,840,10040,4,1]
    getObjectID PubKeyALG_ECDSA = [1,2,840,10045,2,1]
    getObjectID PubKeyALG_DH    = [1,2,840,10046,2,1]
    getObjectID (PubKeyALG_Unknown oid) = oid

sig_table :: [ (OID, SignatureALG) ]
sig_table =
        [ ([1,2,840,113549,1,1,5], SignatureALG HashSHA1 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,4], SignatureALG HashMD5 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,2], SignatureALG HashMD2 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,11], SignatureALG HashSHA256 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,12], SignatureALG HashSHA384 PubKeyALG_RSA)
        , ([1,2,840,10040,4,3],    SignatureALG HashSHA1 PubKeyALG_DSA)
        , ([1,2,840,10045,4,3,1],  SignatureALG HashSHA224 PubKeyALG_ECDSA)
        , ([1,2,840,10045,4,3,2],  SignatureALG HashSHA256 PubKeyALG_ECDSA)
        , ([1,2,840,10045,4,3,3],  SignatureALG HashSHA384 PubKeyALG_ECDSA)
        , ([1,2,840,10045,4,3,4],  SignatureALG HashSHA512 PubKeyALG_ECDSA)
        ]

oidSig :: OID -> SignatureALG
oidSig oid = maybe (SignatureALG_Unknown oid) id $ lookup oid sig_table

sigOID :: SignatureALG -> OID
sigOID (SignatureALG_Unknown oid) = oid
sigOID sig = maybe [] fst $ find ((==) sig . snd) sig_table

instance ASN1Object SignatureALG where
    fromASN1 (Start Sequence:OID oid:Null:End Sequence:xs) =
        Right (oidSig oid, xs)
    fromASN1 (Start Sequence:OID oid:End Sequence:xs) =
        Right (oidSig oid, xs)
    fromASN1 _ =
        Left "fromASN1: X509.SignatureALG: unknown format"
    toASN1 signatureAlg = \xs -> Start Sequence:OID (sigOID signatureAlg):Null:End Sequence:xs
