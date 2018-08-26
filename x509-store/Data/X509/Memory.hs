-- |
-- Module      : Data.X509.Memory
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
--
module Data.X509.Memory
    ( readKeyFileFromMemory
    , readSignedObjectFromMemory
    , pemToKey
    ) where

import Data.ASN1.Types
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
import Data.ASN1.Encoding
import Data.ASN1.Stream
import Data.Maybe
import qualified Data.X509 as X509
import           Data.X509.EC as X509
import Data.PEM (pemParseBS, pemContent, pemName, PEM)
import qualified Data.ByteString as B
import           Crypto.Error (CryptoFailable(..))
import           Crypto.Number.Serialize (os2ip)
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448   as X448
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.Ed25519   as Ed25519
import qualified Crypto.PubKey.Ed448     as Ed448
import qualified Crypto.PubKey.RSA as RSA

readKeyFileFromMemory :: B.ByteString -> [X509.PrivKey]
readKeyFileFromMemory = either (const []) (catMaybes . foldl pemToKey []) . pemParseBS

readSignedObjectFromMemory :: (ASN1Object a, Eq a, Show a)
                           => B.ByteString
                           -> [X509.SignedExact a]
readSignedObjectFromMemory = either (const []) (foldl pemToSigned []) . pemParseBS
  where pemToSigned acc pem =
            case X509.decodeSignedObject $ pemContent pem of
                Left _    -> acc
                Right obj -> obj : acc

pemToKey :: [Maybe X509.PrivKey] -> PEM -> [Maybe X509.PrivKey]
pemToKey acc pem =
    case decodeASN1' BER (pemContent pem) of
        Left _     -> acc
        Right asn1 ->
            case pemName pem of
                "PRIVATE KEY" ->
                    tryRSA asn1 : tryECDH asn1 : tryEdDSA asn1 : tryECDSA asn1 : tryDSA asn1 : acc
                "RSA PRIVATE KEY" ->
                    tryRSA asn1 : acc
                "DSA PRIVATE KEY" ->
                    tryDSA asn1 : acc
                "EC PRIVATE KEY"  ->
                    tryECDSA asn1 : acc
                "X25519 PRIVATE KEY" ->
                    tryECDH asn1 : acc
                "X448 PRIVATE KEY" ->
                    tryECDH asn1 : acc
                "ED25519 PRIVATE KEY" ->
                    tryEdDSA asn1 : acc
                "ED448 PRIVATE KEY" ->
                    tryEdDSA asn1 : acc
                _                 -> acc
  where
        tryRSA asn1 = case rsaFromASN1 asn1 of
                    Left _      -> Nothing
                    Right (k,_) -> Just $ X509.PrivKeyRSA k
        tryDSA asn1 = case dsaFromASN1 asn1 of
                    Left _      -> Nothing
                    Right (k,_) -> Just $ X509.PrivKeyDSA $ DSA.toPrivateKey k
        tryECDSA asn1 = case ecdsaFromASN1 [] asn1 of
                    Left _      -> Nothing
                    Right (k,_) -> Just $ X509.PrivKeyEC k
        tryECDH asn1 = case ecdhFromASN1 asn1 of
                    Left _      -> Nothing
                    Right (k,_) -> Just k
        tryEdDSA asn1 = case eddsaFromASN1 asn1 of
                    Left _      -> Nothing
                    Right (k,_) -> Just k

dsaFromASN1 :: [ASN1] -> Either String (DSA.KeyPair, [ASN1])
dsaFromASN1 (Start Sequence : IntVal n : xs)
    | n /= 0    = Left "fromASN1: DSA.KeyPair: unknown format"
    | otherwise =
        case xs of
            IntVal p : IntVal q : IntVal g : IntVal pub : IntVal priv : End Sequence : xs2 ->
                let params = DSA.Params { DSA.params_p = p, DSA.params_g = g, DSA.params_q = q }
                 in Right (DSA.KeyPair params pub priv, xs2)
            (Start Sequence
             : OID [1, 2, 840, 10040, 4, 1]
             : Start Sequence
             : IntVal p
             : IntVal q
             : IntVal g
             : End Sequence
             : End Sequence
             : OctetString bs
             : End Sequence
             : xs2) ->
                let params = DSA.Params { DSA.params_p = p, DSA.params_g = g, DSA.params_q = q }
                 in case decodeASN1' BER bs of
                        Right [IntVal priv] ->
                            let pub = DSA.calculatePublic params priv
                             in Right (DSA.KeyPair params pub priv, xs2)
                        Right _ -> Left "dsaFromASN1: DSA.PrivateKey: unexpected format"
                        Left  e -> Left $ "dsaFromASN1: DSA.PrivateKey: " ++ show e
            _ ->
                Left "dsaFromASN1: DSA.KeyPair: invalid format (version=0)"
dsaFromASN1 _ = Left "dsaFromASN1: DSA.KeyPair: unexpected format"

ecdsaFromASN1 :: [ASN1] -> [ASN1] -> Either String (X509.PrivKeyEC, [ASN1])
ecdsaFromASN1 curveOid1 (Start Sequence
                         : IntVal 1
                         : OctetString ds
                         : xs) = do
    let (curveOid2, ys) = containerWithTag 0 xs
    privKey <- getPrivKeyEC (os2ip ds) (curveOid2 ++ curveOid1)
    case containerWithTag 1 ys of
        (_, End Sequence : zs) -> return (privKey, zs)
        _                      -> Left "ecdsaFromASN1: unexpected EC format"
ecdsaFromASN1 curveOid1 (Start Sequence
                         : IntVal 0
                         : Start Sequence
                         : OID [1, 2, 840, 10045, 2, 1]
                         : xs) =
    let strError = Left .  ("ecdsaFromASN1: ECDSA.PrivateKey: " ++) . show
        (curveOid2, ys) = getConstructedEnd 0 xs
     in case ys of
            (OctetString bs
             : zs) -> do
                let curveOids = curveOid2 ++ curveOid1
                    inner = either strError (ecdsaFromASN1 curveOids) (decodeASN1' BER bs)
                either Left (\(k, _) -> Right (k, zs)) inner
            _      -> Left "ecdsaFromASN1: unexpected format"
ecdsaFromASN1 _ _ =
    Left "ecdsaFromASN1: unexpected format"

getPrivKeyEC :: ECDSA.PrivateNumber -> [ASN1] -> Either String X509.PrivKeyEC
getPrivKeyEC _ []                 = Left "ecdsaFromASN1: curve is missing"
getPrivKeyEC d (OID curveOid : _) =
    case X509.lookupCurveNameByOID curveOid of
        Just name -> Right X509.PrivKeyEC_Named { X509.privkeyEC_name = name
                                                , X509.privkeyEC_priv = d
                                                }
        Nothing   -> Left ("ecdsaFromASN1: unknown curve " ++ show curveOid)
getPrivKeyEC d (Null : xs)        = getPrivKeyEC d xs
getPrivKeyEC d (Start Sequence
                : IntVal 1
                : Start Sequence
                : OID [1, 2, 840, 10045, 1, 1]
                : IntVal prime
                : End Sequence
                : Start Sequence
                : OctetString a
                : OctetString b
                : BitString seed
                : End Sequence
                : OctetString generator
                : IntVal order
                : IntVal cofactor
                : End Sequence
                : _)              =
    Right X509.PrivKeyEC_Prime
              { X509.privkeyEC_priv      = d
              , X509.privkeyEC_a         = os2ip a
              , X509.privkeyEC_b         = os2ip b
              , X509.privkeyEC_prime     = prime
              , X509.privkeyEC_generator = X509.SerializedPoint generator
              , X509.privkeyEC_order     = order
              , X509.privkeyEC_cofactor  = cofactor
              , X509.privkeyEC_seed      = os2ip $ bitArrayGetData seed
              }
getPrivKeyEC _ _                  = Left "ecdsaFromASN1: unexpected curve format"

containerWithTag :: ASN1Tag -> [ASN1] -> ([ASN1], [ASN1])
containerWithTag etag (Start (Container _ atag) : xs)
    | etag == atag = getConstructedEnd 0 xs
containerWithTag _    xs = ([], xs)

primitiveWithTag :: ASN1Tag -> [ASN1] -> (Maybe B.ByteString, [ASN1])
primitiveWithTag etag (Other _ atag bs : xs)
    | etag == atag = (Just bs, xs)
primitiveWithTag _    xs = (Nothing, xs)

ecdhFromASN1 :: [ASN1] -> Either String (X509.PrivKey, [ASN1])
ecdhFromASN1 ( Start Sequence
               : IntVal 0
               : Start Sequence
               : OID [1, 3, 101, 110]
               : End Sequence
               : OctetString bs
               : xs) =
    case decodeASN1' BER bs of
        Right [OctetString key] ->
                case X25519.secretKey key of
                    CryptoPassed s -> Right (X509.PrivKeyX25519 s, xs)
                    CryptoFailed e -> Left $ "ecdhFromASN1: X25519.PrivateKey: invalid secret key: " ++ show e
        Right _ -> Left "ecdhFromASN1: X25519.PrivateKey: unexpected format"
        Left  e -> Left $ "ecdhFromASN1: X25519.PrivateKey: " ++ show e
ecdhFromASN1 ( Start Sequence
               : IntVal 0
               : Start Sequence
               : OID [1, 3, 101, 111]
               : End Sequence
               : OctetString bs
               : xs) =
    case decodeASN1' BER bs of
        Right [OctetString key] ->
                case X448.secretKey key of
                    CryptoPassed s -> Right (X509.PrivKeyX448 s, xs)
                    CryptoFailed e -> Left $ "ecdhFromASN1: X448.PrivateKey: invalid secret key: " ++ show e
        Right _ -> Left "ecdhFromASN1: X448.PrivateKey: unexpected format"
        Left  e -> Left $ "ecdhFromASN1: X448.PrivateKey: " ++ show e
ecdhFromASN1 ( Start Sequence
               : IntVal 1
               : Start Sequence
               : oid@(OID _)
               : End Sequence
               : os@(OctetString _)
               : xs) = do
    let (_, ys) = containerWithTag 0 xs
    case primitiveWithTag 1 ys of
        (_, End Sequence : zs) -> ecdhFromASN1 (Start Sequence : IntVal 0 : Start Sequence : oid : End Sequence : os : zs)
        _                      -> Left "ecdhFromASN1: unexpected V2 format"
ecdhFromASN1 _ =
    Left "ecdhFromASN1: unexpected format"

eddsaFromASN1 :: [ASN1] -> Either String (X509.PrivKey, [ASN1])
eddsaFromASN1 ( Start Sequence
               : IntVal 0
               : Start Sequence
               : OID [1, 3, 101, 112]
               : End Sequence
               : OctetString bs
               : xs) =
    case decodeASN1' BER bs of
        Right [OctetString key] ->
                case Ed25519.secretKey key of
                    CryptoPassed s -> Right (X509.PrivKeyEd25519 s, xs)
                    CryptoFailed e -> Left $ "eddsaFromASN1: Ed25519.PrivateKey: invalid secret key: " ++ show e
        Right _ -> Left "eddsaFromASN1: Ed25519.PrivateKey: unexpected format"
        Left  e -> Left $ "eddsaFromASN1: Ed25519.PrivateKey: " ++ show e
eddsaFromASN1 ( Start Sequence
               : IntVal 0
               : Start Sequence
               : OID [1, 3, 101, 113]
               : End Sequence
               : OctetString bs
               : xs) =
    case decodeASN1' BER bs of
        Right [OctetString key] ->
                case Ed448.secretKey key of
                    CryptoPassed s -> Right (X509.PrivKeyEd448 s, xs)
                    CryptoFailed e -> Left $ "eddsaFromASN1: Ed448.PrivateKey: invalid secret key: " ++ show e
        Right _ -> Left "eddsaFromASN1: Ed448.PrivateKey: unexpected format"
        Left  e -> Left $ "eddsaFromASN1: Ed448.PrivateKey: " ++ show e
eddsaFromASN1 ( Start Sequence
               : IntVal 1
               : Start Sequence
               : oid@(OID _)
               : End Sequence
               : os@(OctetString _)
               : xs) = do
    let (_, ys) = containerWithTag 0 xs
    case primitiveWithTag 1 ys of
        (_, End Sequence : zs) -> eddsaFromASN1 (Start Sequence : IntVal 0 : Start Sequence : oid : End Sequence : os : zs)
        _                      -> Left "eddsaFromASN1: unexpected V2 format"
eddsaFromASN1 _ =
    Left "eddsaFromASN1: unexpected format"

rsaFromASN1 :: [ASN1] -> Either String (RSA.PrivateKey, [ASN1])
rsaFromASN1 (Start Sequence
             : IntVal 0
             : IntVal n
             : IntVal e
             : IntVal d
             : IntVal p1
             : IntVal p2
             : IntVal pexp1
             : IntVal pexp2
             : IntVal pcoef
             : End Sequence
             : xs) = Right (privKey, xs)
  where
    calculate_modulus m i = if (2 ^ (i * 8)) > m then i else calculate_modulus m (i+1)
    pubKey  = RSA.PublicKey { RSA.public_size = calculate_modulus n 1
                            , RSA.public_n    = n
                            , RSA.public_e    = e
                            }
    privKey = RSA.PrivateKey { RSA.private_pub  = pubKey
                             , RSA.private_d    = d
                             , RSA.private_p    = p1
                             , RSA.private_q    = p2
                             , RSA.private_dP   = pexp1
                             , RSA.private_dQ   = pexp2
                             , RSA.private_qinv = pcoef
                             }

rsaFromASN1 ( Start Sequence
             : IntVal 0
             : Start Sequence
             : OID [1, 2, 840, 113549, 1, 1, 1]
             : Null
             : End Sequence
             : OctetString bs
             : xs) =
    let inner = either strError rsaFromASN1 $ decodeASN1' BER bs
        strError = Left .  ("rsaFromASN1: RSA.PrivateKey: " ++) . show
     in either Left (\(k, _) -> Right (k, xs)) inner
rsaFromASN1 _ =
    Left "rsaFromASN1: unexpected format"
