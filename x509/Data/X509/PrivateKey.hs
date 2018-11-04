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
import Data.Maybe (fromMaybe)
import Data.Word (Word)

import Data.ByteArray (ByteArrayAccess, convert)
import qualified Data.ByteString as B

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
import Data.ASN1.Stream (getConstructedEnd)

import Data.X509.AlgorithmIdentifier
import Data.X509.PublicKey (SerializedPoint(..))
import Data.X509.OID (lookupByOID, lookupOID, curvesOIDTable)

import Crypto.Error (CryptoFailable(..))
import Crypto.Number.Serialize (i2osp, os2ip)
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

instance ASN1Object PrivKey where
    fromASN1 = privkeyFromASN1
    toASN1 = privkeyToASN1

privkeyFromASN1 :: [ASN1] -> Either String (PrivKey, [ASN1])
privkeyFromASN1 asn1 =
  (mapFst PrivKeyRSA <$> rsaFromASN1 asn1) <!>
  (mapFst PrivKeyDSA <$> dsaFromASN1 asn1) <!>
  (mapFst PrivKeyEC <$> ecdsaFromASN1 asn1) <!>
  newcurveFromASN1 asn1
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

newcurveFromASN1 :: [ASN1] -> Either String (PrivKey, [ASN1])
newcurveFromASN1 ( Start Sequence
                  : IntVal v
                  : Start Sequence
                  : OID oid
                  : End Sequence
                  : OctetString bs
                  : xs)
    | isValidVersion v = do
        let (_, ys) = containerWithTag 0 xs
        case primitiveWithTag 1 ys of
            (_, End Sequence : zs) ->
                case getP oid of
                    Just (name, parse) -> do
                        let err s = Left (name ++ ".SecretKey.fromASN1: " ++ s)
                        case decodeASN1' BER bs of
                            Right [OctetString key] ->
                                case parse key of
                                    CryptoPassed s -> Right (s, zs)
                                    CryptoFailed e -> err ("invalid secret key: " ++ show e)
                            Right _ -> err "unexpected inner format"
                            Left  e -> err (show e)
                    Nothing -> Left ("newcurveFromASN1: unexpected OID " ++ show oid)
            _ -> Left "newcurveFromASN1: unexpected end format"
    | otherwise = Left ("newcurveFromASN1: unexpected version: " ++ show v)
  where
    getP [1,3,101,110] = Just ("X25519", fmap PrivKeyX25519 . X25519.secretKey)
    getP [1,3,101,111] = Just ("X448", fmap PrivKeyX448 . X448.secretKey)
    getP [1,3,101,112] = Just ("Ed25519", fmap PrivKeyEd25519 . Ed25519.secretKey)
    getP [1,3,101,113] = Just ("Ed448", fmap PrivKeyEd448 . Ed448.secretKey)
    getP _             = Nothing
    isValidVersion version = version >= 0 && version <= 1
newcurveFromASN1 _ =
    Left "newcurveFromASN1: unexpected format"

containerWithTag :: ASN1Tag -> [ASN1] -> ([ASN1], [ASN1])
containerWithTag etag (Start (Container _ atag) : xs)
    | etag == atag = getConstructedEnd 0 xs
containerWithTag _    xs = ([], xs)

primitiveWithTag :: ASN1Tag -> [ASN1] -> (Maybe B.ByteString, [ASN1])
primitiveWithTag etag (Other _ atag bs : xs)
    | etag == atag = (Just bs, xs)
primitiveWithTag _    xs = (Nothing, xs)

privkeyToASN1 :: PrivKey -> ASN1S
privkeyToASN1 (PrivKeyRSA rsa) = rsaToASN1 rsa
privkeyToASN1 (PrivKeyDSA dsa) = dsaToASN1 dsa
privkeyToASN1 (PrivKeyEC ecdsa) = ecdsaToASN1 ecdsa
privkeyToASN1 (PrivKeyX25519 k)  = newcurveToASN1 [1,3,101,110] k
privkeyToASN1 (PrivKeyX448 k)    = newcurveToASN1 [1,3,101,111] k
privkeyToASN1 (PrivKeyEd25519 k) = newcurveToASN1 [1,3,101,112] k
privkeyToASN1 (PrivKeyEd448 k)   = newcurveToASN1 [1,3,101,113] k

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
    err = error . ("ECDSA.PrivateKey.toASN1: " ++)
    oid = fromMaybe (err $ "missing named curve " ++ show curveName)
                    (lookupOID curvesOIDTable curveName)
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

newcurveToASN1 :: ByteArrayAccess key => OID -> key -> ASN1S
newcurveToASN1 oid key = (++)
    [ Start Sequence, IntVal 0, Start Sequence, OID oid, End Sequence
    , OctetString (encodeASN1' DER [OctetString $ convert key])
    , End Sequence
    ]

mapLeft :: (a0 -> a1) -> Either a0 b -> Either a1 b
mapLeft f (Left x) = Left (f x)
mapLeft _ (Right x) = Right x

-- | Convert a Private key to the Public Key Algorithm type
privkeyToAlg :: PrivKey -> PubKeyALG
privkeyToAlg (PrivKeyRSA _)         = PubKeyALG_RSA
privkeyToAlg (PrivKeyDSA _)         = PubKeyALG_DSA
privkeyToAlg (PrivKeyEC _)          = PubKeyALG_EC
privkeyToAlg (PrivKeyX25519 _)      = PubKeyALG_X25519
privkeyToAlg (PrivKeyX448 _)        = PubKeyALG_X448
privkeyToAlg (PrivKeyEd25519 _)     = PubKeyALG_Ed25519
privkeyToAlg (PrivKeyEd448 _)       = PubKeyALG_Ed448
