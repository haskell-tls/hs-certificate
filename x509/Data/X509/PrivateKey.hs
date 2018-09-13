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

import Control.Applicative ((<$>), pure)
import Data.Word (Word)

import qualified Data.ByteString as B

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray

import Data.X509.AlgorithmIdentifier
import Data.X509.PublicKey (SerializedPoint(..))
import Data.X509.OID (lookupByOID, curvesOIDTable)

import Crypto.Number.Serialize (i2osp, os2ip)
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.Types as ECC

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
    deriving (Show,Eq)

instance ASN1Object PrivKey where
    fromASN1 = privkeyFromASN1
    toASN1 = privkeyToASN1

privkeyFromASN1 :: [ASN1] -> Either String (PrivKey, [ASN1])
privkeyFromASN1 asn1 =
  (mapFst PrivKeyRSA <$> rsaFromASN1 asn1) <!>
  (mapFst PrivKeyDSA <$> dsaFromASN1 asn1) <!>
  (mapFst PrivKeyEC <$> ecdsaFromASN1 asn1)
  where
    mapFst f (a, b) = (f a, b)

    Left _ <!> b = b
    a      <!> _ = a

rsaFromASN1 :: [ASN1] -> Either String (RSA.PrivateKey, [ASN1])
rsaFromASN1 (Start Sequence : IntVal 0 : IntVal n : IntVal e : IntVal d
    : IntVal p : IntVal q : IntVal dP : IntVal dQ : IntVal qinv
    : End Sequence : as) = pure (key, as)
  where
    key = RSA.PrivateKey (RSA.PublicKey (go n 1) n e) d p q dP dQ qinv
    go m i
        | 2 ^ (i * 8) > m = i
        | otherwise = go m (i + 1)
rsaFromASN1 (Start Sequence : IntVal 0 : Start Sequence
    : OID [1, 2, 840, 113549, 1, 1, 1] : Null : End Sequence
    : OctetString bytes : End Sequence : as) = do
        asn1 <- mapLeft failure (decodeASN1' BER bytes)
        fmap (const as) <$> rsaFromASN1 asn1
  where
    failure = ("rsaFromASN1: " ++) . show
rsaFromASN1 _ = Left "rsaFromASN1: unexpected format"

dsaFromASN1 :: [ASN1] -> Either String (DSA.PrivateKey, [ASN1])
dsaFromASN1 (Start Sequence : IntVal 0 : IntVal p : IntVal q : IntVal g
    : IntVal _ : IntVal x : End Sequence : as) =
        pure (DSA.PrivateKey (DSA.Params p g q) x, as)
dsaFromASN1 (Start Sequence : IntVal 0 : Start Sequence
    : OID [1, 2, 840, 10040, 4, 1] : Start Sequence : IntVal p : IntVal q
    : IntVal g : End Sequence : End Sequence : OctetString bytes
    : End Sequence : as) = case decodeASN1' BER bytes of
        Right [IntVal x] -> pure (DSA.PrivateKey (DSA.Params p g q) x, as)
        Right _ -> Left "DSA.PrivateKey.fromASN1: unexpected format"
        Left e -> Left $ "DSA.PrivateKey.fromASN1: " ++ show e
dsaFromASN1 _ = Left "DSA.PrivateKey.fromASN1: unexpected format"

ecdsaFromASN1 :: [ASN1] -> Either String (PrivKeyEC, [ASN1])
ecdsaFromASN1 = go []
  where
    failing = ("ECDSA.PrivateKey.fromASN1: " ++)

    go acc (Start Sequence : IntVal 1 : OctetString bytes : rest) = do
        key <- subgo (oid ++ acc)
        case rest'' of
            End Sequence : rest''' -> pure (key, rest''')
            _ -> Left $ failing "unexpected EC format"
      where
        d = os2ip bytes
        (oid, rest') = spanTag 0 rest
        (_, rest'') = spanTag 1 rest'
        subgo (OID oid_ : _) = maybe failure success mcurve
          where
            failure = Left $ failing $ "unknown curve " ++ show oid_
            success = Right . flip PrivKeyEC_Named d
            mcurve = lookupByOID curvesOIDTable oid_
        subgo (Start Sequence : IntVal 1 : Start Sequence
            : OID [1, 2, 840, 10045, 1, 1] : IntVal p : End Sequence
            : Start Sequence : OctetString a : OctetString b : BitString s
            : End Sequence : OctetString g : IntVal o : IntVal c
            : End Sequence : _) =
                pure $ PrivKeyEC_Prime d a' b' p g' o c s'
          where
            a' = os2ip a
            b' = os2ip b
            g' = SerializedPoint g
            s' = os2ip $ bitArrayGetData s
        subgo (Null : rest_) = subgo rest_
        subgo [] = Left $ failing "curve is missing"
        subgo _ = Left $ failing "unexpected curve format"
    go acc (Start Sequence : IntVal 0 : Start Sequence
        : OID [1, 2, 840, 10045, 2, 1] : rest) = case rest' of
            (OctetString bytes : rest'') -> do
                asn1 <- mapLeft (failing . show) (decodeASN1' BER bytes)
                fmap (const rest'') <$> go (oid ++ acc) asn1
            _ -> Left $ failing "unexpected EC format"
      where
        (oid, rest') = spanEnd 0 rest
    go _ _ = Left $ failing "unexpected EC format"

    spanEnd :: Word -> [ASN1] -> ([ASN1], [ASN1])
    spanEnd = loop id
      where
        loop dlist n (a@(Start _) : as) = loop (dlist . (a :)) (n + 1) as
        loop dlist 0 (End _ : as) = (dlist [], as)
        loop dlist n (a@(End _) : as) = loop (dlist . (a :)) (n - 1) as
        loop dlist n (a : as) = loop (dlist . (a :)) n as
        loop dlist _ [] = (dlist [], [])

    spanTag :: Int -> [ASN1] -> ([ASN1], [ASN1])
    spanTag a (Start (Container _ b) : as) | a == b = spanEnd 0 as
    spanTag _ as = ([], as)

privkeyToASN1 :: PrivKey -> ASN1S
privkeyToASN1 (PrivKeyRSA rsa) = rsaToASN1 rsa
privkeyToASN1 (PrivKeyDSA dsa) = dsaToASN1 dsa
privkeyToASN1 (PrivKeyEC ecdsa) = ecdsaToASN1 ecdsa

rsaToASN1 :: RSA.PrivateKey -> ASN1S
rsaToASN1 key = (++)
    [ Start Sequence, IntVal 0, IntVal n, IntVal e, IntVal d, IntVal p
    , IntVal q, IntVal dP, IntVal dQ, IntVal qinv, End Sequence
    ]
  where
    RSA.PrivateKey (RSA.PublicKey _ n e) d p q dP dQ qinv = key

dsaToASN1 :: DSA.PrivateKey -> ASN1S
dsaToASN1 (DSA.PrivateKey params@(DSA.Params p g q) y) = (++)
    [ Start Sequence, IntVal 0, IntVal p, IntVal q, IntVal g, IntVal x
    , IntVal y, End Sequence
    ]
  where
    x = DSA.calculatePublic params y

ecdsaToASN1 :: PrivKeyEC -> ASN1S
ecdsaToASN1 (PrivKeyEC_Named curveName d) = (++)
    [ Start Sequence, IntVal 1, OctetString (i2osp d)
    , Start (Container Context 0), OID oid, End (Container Context 0)
    , End Sequence
    ]
  where
    oid = case curveName of
        ECC.SEC_p112r1 -> [1, 3, 132, 0, 6]
        ECC.SEC_p112r2 -> [1, 3, 132, 0, 7]
        ECC.SEC_p128r1 -> [1, 3, 132, 0, 28]
        ECC.SEC_p128r2 -> [1, 3, 132, 0, 29]
        ECC.SEC_p160k1 -> [1, 3, 132, 0, 9]
        ECC.SEC_p160r1 -> [1, 3, 132, 0, 8]
        ECC.SEC_p160r2 -> [1, 3, 132, 0, 30]
        ECC.SEC_p192k1 -> [1, 3, 132, 0, 31]
        ECC.SEC_p192r1 -> [1, 2, 840, 10045, 3, 1, 1]
        ECC.SEC_p224k1 -> [1, 3, 132, 0, 32]
        ECC.SEC_p224r1 -> [1, 3, 132, 0, 33]
        ECC.SEC_p256k1 -> [1, 3, 132, 0, 10]
        ECC.SEC_p256r1 -> [1, 2, 840, 10045, 3, 1, 7]
        ECC.SEC_p384r1 -> [1, 3, 132, 0, 34]
        ECC.SEC_p521r1 -> [1, 3, 132, 0, 35]
        ECC.SEC_t113r1 -> [1, 3, 132, 0, 4]
        ECC.SEC_t113r2 -> [1, 3, 132, 0, 5]
        ECC.SEC_t131r1 -> [1, 3, 132, 0, 22]
        ECC.SEC_t131r2 -> [1, 3, 132, 0, 23]
        ECC.SEC_t163k1 -> [1, 3, 132, 0, 1]
        ECC.SEC_t163r1 -> [1, 3, 132, 0, 2]
        ECC.SEC_t163r2 -> [1, 3, 132, 0, 15]
        ECC.SEC_t193r1 -> [1, 3, 132, 0, 24]
        ECC.SEC_t193r2 -> [1, 3, 132, 0, 25]
        ECC.SEC_t233k1 -> [1, 3, 132, 0, 26]
        ECC.SEC_t233r1 -> [1, 3, 132, 0, 27]
        ECC.SEC_t239k1 -> [1, 3, 132, 0, 3]
        ECC.SEC_t283k1 -> [1, 3, 132, 0, 16]
        ECC.SEC_t283r1 -> [1, 3, 132, 0, 17]
        ECC.SEC_t409k1 -> [1, 3, 132, 0, 36]
        ECC.SEC_t409r1 -> [1, 3, 132, 0, 37]
        ECC.SEC_t571k1 -> [1, 3, 132, 0, 38]
        ECC.SEC_t571r1 -> [1, 3, 132, 0, 39]
ecdsaToASN1 (PrivKeyEC_Prime d a b p g o c s) = (++)
    [ Start Sequence, IntVal 1, OctetString (i2osp d)
    , Start (Container Context 0), Start Sequence, IntVal 1
    , Start Sequence, OID [1, 2, 840, 10045, 1, 1], IntVal p, End Sequence
    , Start Sequence, OctetString a', OctetString b', BitString s'
    , End Sequence, OctetString g' , IntVal o, IntVal c, End Sequence
    , End (Container Context 0), End Sequence
    ]
  where
    a' = i2osp a
    b' = i2osp b
    SerializedPoint g' = g
    s' = BitArray (8 * fromIntegral (B.length bytes)) bytes
      where
        bytes = i2osp s

mapLeft :: (a0 -> a1) -> Either a0 b -> Either a1 b
mapLeft f (Left x) = Left (f x)
mapLeft _ (Right x) = Right x

-- | Convert a Private key to the Public Key Algorithm type
privkeyToAlg :: PrivKey -> PubKeyALG
privkeyToAlg (PrivKeyRSA _)         = PubKeyALG_RSA
privkeyToAlg (PrivKeyDSA _)         = PubKeyALG_DSA
privkeyToAlg (PrivKeyEC _)          = PubKeyALG_EC
