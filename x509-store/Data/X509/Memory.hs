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
import Data.ASN1.Encoding
import Data.Maybe
import qualified Data.X509 as X509
import Data.PEM (pemParseBS, pemContent, pemName, PEM)
import qualified Data.ByteString as B
import qualified Crypto.PubKey.DSA as DSA
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
                    tryRSA asn1 : tryDSA asn1 : acc
                "RSA PRIVATE KEY" ->
                    tryRSA asn1 : acc
                "DSA PRIVATE KEY" ->
                    tryDSA asn1 : acc
                _                 -> acc
  where
        tryRSA asn1 = case rsaFromASN1 asn1 of
                    Left _      -> Nothing
                    Right (k,_) -> Just $ X509.PrivKeyRSA k
        tryDSA asn1 = case dsaFromASN1 asn1 of
                    Left _      -> Nothing
                    Right (k,_) -> Just $ X509.PrivKeyDSA $ DSA.toPrivateKey k

dsaFromASN1 :: [ASN1] -> Either String (DSA.KeyPair, [ASN1])
dsaFromASN1 (Start Sequence : IntVal n : xs)
    | n /= 0    = Left "fromASN1: DSA.KeyPair: unknown format"
    | otherwise =
        case xs of
            IntVal p : IntVal q : IntVal g : IntVal pub : IntVal priv : End Sequence : xs2 ->
                let params = DSA.Params { DSA.params_p = p, DSA.params_g = g, DSA.params_q = q }
                 in Right (DSA.KeyPair params pub priv, xs2)
            _ ->
                Left "dsaFromASN1: DSA.KeyPair: invalid format (version=0)"
dsaFromASN1 _ = Left "dsaFromASN1: DSA.KeyPair: unexpected format"

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
