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
    | PubKeyALG_RSAPSS      -- ^ RSA PSS Key algorithm (RFC 3447)
    | PubKeyALG_DSA         -- ^ DSA Public Key algorithm
    | PubKeyALG_EC          -- ^ ECDSA & ECDH Public Key algorithm
    | PubKeyALG_X25519      -- ^ ECDH 25519 key agreement
    | PubKeyALG_X448        -- ^ ECDH 448 key agreement
    | PubKeyALG_Ed25519     -- ^ EdDSA 25519 signature algorithm
    | PubKeyALG_Ed448       -- ^ EdDSA 448 signature algorithm
    | PubKeyALG_DH          -- ^ Diffie Hellman Public Key algorithm
    | PubKeyALG_Unknown OID -- ^ Unknown Public Key algorithm
    deriving (Show,Eq)

-- | Signature Algorithm, often composed of a public key algorithm and a hash
-- algorithm.  For some signature algorithms the hash algorithm is intrinsic to
-- the public key algorithm and is not needed in the data type.
data SignatureALG =
      SignatureALG HashALG PubKeyALG
    | SignatureALG_IntrinsicHash PubKeyALG
    | SignatureALG_Unknown OID
    deriving (Show,Eq)

instance OIDable PubKeyALG where
    getObjectID PubKeyALG_RSA    = [1,2,840,113549,1,1,1]
    getObjectID PubKeyALG_RSAPSS = [1,2,840,113549,1,1,10]
    getObjectID PubKeyALG_DSA    = [1,2,840,10040,4,1]
    getObjectID PubKeyALG_EC     = [1,2,840,10045,2,1]
    getObjectID PubKeyALG_X25519    = [1,3,101,110]
    getObjectID PubKeyALG_X448      = [1,3,101,111]
    getObjectID PubKeyALG_Ed25519   = [1,3,101,112]
    getObjectID PubKeyALG_Ed448     = [1,3,101,113]
    getObjectID PubKeyALG_DH     = [1,2,840,10046,2,1]
    getObjectID (PubKeyALG_Unknown oid) = oid

sig_table :: [ (OID, SignatureALG) ]
sig_table =
        [ ([1,2,840,113549,1,1,5], SignatureALG HashSHA1 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,4], SignatureALG HashMD5 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,2], SignatureALG HashMD2 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,11], SignatureALG HashSHA256 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,12], SignatureALG HashSHA384 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,13], SignatureALG HashSHA512 PubKeyALG_RSA)
        , ([1,2,840,113549,1,1,14], SignatureALG HashSHA224 PubKeyALG_RSA)
        , ([1,2,840,10040,4,3],    SignatureALG HashSHA1 PubKeyALG_DSA)
        , ([1,2,840,10045,4,1],    SignatureALG HashSHA1 PubKeyALG_EC)
        , ([1,2,840,10045,4,3,1],  SignatureALG HashSHA224 PubKeyALG_EC)
        , ([1,2,840,10045,4,3,2],  SignatureALG HashSHA256 PubKeyALG_EC)
        , ([1,2,840,10045,4,3,3],  SignatureALG HashSHA384 PubKeyALG_EC)
        , ([1,2,840,10045,4,3,4],  SignatureALG HashSHA512 PubKeyALG_EC)
        , ([2,16,840,1,101,3,4,2,1],  SignatureALG HashSHA256 PubKeyALG_RSAPSS)
        , ([2,16,840,1,101,3,4,2,2],  SignatureALG HashSHA384 PubKeyALG_RSAPSS)
        , ([2,16,840,1,101,3,4,2,3],  SignatureALG HashSHA512 PubKeyALG_RSAPSS)
        , ([2,16,840,1,101,3,4,2,4],  SignatureALG HashSHA224 PubKeyALG_RSAPSS)
        , ([2,16,840,1,101,3,4,3,1],  SignatureALG HashSHA224 PubKeyALG_DSA)
        , ([2,16,840,1,101,3,4,3,2],  SignatureALG HashSHA256 PubKeyALG_DSA)
        , ([1,3,101,112], SignatureALG_IntrinsicHash PubKeyALG_Ed25519)
        , ([1,3,101,113], SignatureALG_IntrinsicHash PubKeyALG_Ed448)
        ]

oidSig :: OID -> SignatureALG
oidSig oid = maybe (SignatureALG_Unknown oid) id $ lookup oid sig_table

sigOID :: SignatureALG -> OID
sigOID (SignatureALG_Unknown oid) = oid
sigOID sig = maybe (error ("unknown OID for " ++ show sig)) fst $ find ((==) sig . snd) sig_table

-- | PSS salt length. Always assume ``-sigopt rsa_pss_saltlen:-1``
saltLen :: HashALG -> Integer
saltLen HashSHA256 = 32
saltLen HashSHA384 = 48
saltLen HashSHA512 = 64
saltLen HashSHA224 = 28
saltLen _          = error "toASN1: X509.SignatureAlg.HashAlg: Unknown hash"

instance ASN1Object SignatureALG where
    fromASN1 (Start Sequence:OID oid:Null:End Sequence:xs) =
        case oidSig oid of
            SignatureALG_IntrinsicHash _ ->
                Left "fromASN1: X509.SignatureALG: EdDSA requires absent parameter"
            signatureAlg -> Right (signatureAlg, xs)
    fromASN1 (Start Sequence:OID oid:End Sequence:xs) =
        Right (oidSig oid, xs)
    fromASN1 (Start Sequence:OID [1,2,840,113549,1,1,10]:Start Sequence:Start _:Start Sequence:OID hash1:End Sequence:End _:Start _:Start Sequence:OID [1,2,840,113549,1,1,8]:Start Sequence:OID _hash2:End Sequence:End Sequence:End _:Start _: IntVal _iv: End _: End Sequence : End Sequence:xs) =
        Right (oidSig hash1, xs)
    fromASN1 (Start Sequence:OID [1,2,840,113549,1,1,10]:Start Sequence:Start _:Start Sequence:OID hash1:Null:End Sequence:End _:Start _:Start Sequence:OID [1,2,840,113549,1,1,8]:Start Sequence:OID _hash2:Null:End Sequence:End Sequence:End _:Start _: IntVal _iv: End _: End Sequence : End Sequence:xs) =
        Right (oidSig hash1, xs)
    fromASN1 _ =
        Left "fromASN1: X509.SignatureALG: unknown format"
    toASN1 (SignatureALG_Unknown oid) = \xs -> Start Sequence:OID oid:Null:End Sequence:xs
    toASN1 signatureAlg@(SignatureALG hashAlg PubKeyALG_RSAPSS) = \xs -> Start Sequence:OID [1,2,840,113549,1,1,10]:Start Sequence:Start (Container Context 0):Start Sequence:OID (sigOID signatureAlg):End Sequence:End (Container Context 0):Start (Container Context 1): Start Sequence:OID [1,2,840,113549,1,1,8]:Start Sequence:OID (sigOID signatureAlg):End Sequence:End Sequence:End (Container Context 1):Start (Container Context 2):IntVal (saltLen hashAlg):End (Container Context 2):End Sequence:End Sequence:xs
    toASN1 signatureAlg@(SignatureALG_IntrinsicHash _) = \xs -> Start Sequence:OID (sigOID signatureAlg):End Sequence:xs
    toASN1 signatureAlg = \xs -> Start Sequence:OID (sigOID signatureAlg):Null:End Sequence:xs
