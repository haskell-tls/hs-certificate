module Data.X509.PublicKey
    ( PubKey(..)
    , pubkeyToAlg
    ) where

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray

import Data.X509.Internal
import Data.X509.AlgorithmIdentifier

import qualified Crypto.Types.PubKey.RSA as RSA
import qualified Crypto.Types.PubKey.DSA as DSA
import Data.Word

import qualified Data.ByteString as B

-- FIXME this doesn't identify ECDSA_Hash_SHA384, but the curve name secp384r1
-- with implicit SHA384 hashing.
data ECDSA_Hash = ECDSA_Hash_SHA384
                deriving (Show,Eq)

data PubKey =
          PubKeyRSA RSA.PublicKey -- ^ RSA public key
        | PubKeyDSA DSA.PublicKey -- ^ DSA public key
        | PubKeyDH (Integer,Integer,Integer,Maybe Integer,([Word8], Integer))
                                    -- ^ DH format with (p,g,q,j,(seed,pgenCounter))
        | PubKeyECDSA ECDSA_Hash B.ByteString
        | PubKeyUnknown OID B.ByteString -- ^ unrecognized format
        deriving (Show,Eq)

-- Public key are in the format:
--
-- Start Sequence
--      OID (Public key algorithm)
--      [public key specific format]
--      BitString
-- End Sequence
instance ASN1Object PubKey where
    fromASN1 (Start Sequence:Start Sequence:OID pkalg:xs)
        | pkalg == getObjectID PubKeyALG_RSA =
            case xs of
                Null:End Sequence:BitString bits:End Sequence:xs2 -> decodeASN1Err "RSA" bits xs2 (toPubKeyRSA . fromASN1)
                _ -> Left "fromASN1: X509.PubKey: unknown RSA format"
        | pkalg == getObjectID PubKeyALG_DSA   =
            case xs of
                Start Sequence:IntVal p:IntVal q:IntVal g:End Sequence:End Sequence:BitString bits:End Sequence:xs2 ->
                    decodeASN1Err "DSA" bits xs2 (\l -> case l of
                        [IntVal dsapub] ->
                            let pubkey = DSA.PublicKey { DSA.public_params = DSA.Params { DSA.params_p = p
                                                                                        , DSA.params_q = q
                                                                                        , DSA.params_g = g
                                                                                        }
                                                                           , DSA.public_y = dsapub }
                             in Right (PubKeyDSA pubkey, xs2)
                        _ -> Left "fromASN1: X509.PubKey: unknown DSA format"
                        )
                _ -> Left "fromASN1: X509.PubKey: unknown DSA format"
        | pkalg == getObjectID PubKeyALG_ECDSA =
            case xs of
                OID [1,3,132,0,34]:End Sequence:BitString bits:End Sequence:xs2 -> Right (PubKeyECDSA ECDSA_Hash_SHA384 (bitArrayGetData bits), xs2) -- secp384r1
                _ -> Left "fromASN1: X509.PubKey: unknown ECDSA format"
        | otherwise = undefined
        where decodeASN1Err format bits xs2 f =
                case decodeASN1' BER (bitArrayGetData bits) of
                    Left err -> Left ("fromASN1: X509.PubKey " ++ format ++ " bitarray cannot be parsed: " ++ show err)
                    Right s  -> case f s of
                                    Left err -> Left err
                                    Right (r, xsinner) -> Right (r, xsinner ++ xs2)
              toPubKeyRSA = either Left (\(rsaKey, r) -> Right (PubKeyRSA rsaKey, r))
            
    fromASN1 l = Left ("fromASN1: X509.PubKey: unknown format:" ++ show l)
    toASN1 a = \xs -> encodePK a ++ xs

pubkeyToAlg :: PubKey -> PubKeyALG
pubkeyToAlg (PubKeyRSA _)         = PubKeyALG_RSA
pubkeyToAlg (PubKeyDSA _)         = PubKeyALG_DSA
pubkeyToAlg (PubKeyDH _)          = PubKeyALG_DH
pubkeyToAlg (PubKeyECDSA _ _)     = PubKeyALG_ECDSA
pubkeyToAlg (PubKeyUnknown oid _) = PubKeyALG_Unknown oid

encodePK :: PubKey -> [ASN1]
encodePK key = asn1Container Sequence (encodeInner key)
  where
    pkalg = OID $ getObjectID $ pubkeyToAlg key
    encodeInner (PubKeyRSA pubkey) =
        asn1Container Sequence [pkalg,Null] ++ [BitString $ toBitArray bits 0]
      where bits = encodeASN1' DER $ asn1Container Sequence [IntVal (RSA.public_n pubkey), IntVal (RSA.public_e pubkey)]
    encodeInner (PubKeyDSA pubkey) =
        asn1Container Sequence ([pkalg] ++ dsaseq) ++ [BitString $ toBitArray bits 0]
      where
        dsaseq = asn1Container Sequence [IntVal (DSA.params_p params)
                                        ,IntVal (DSA.params_q params)
                                        ,IntVal (DSA.params_g params)]
        params = DSA.public_params pubkey
        bits   = encodeASN1' DER [IntVal $ DSA.public_y pubkey]
    encodeInner (PubKeyECDSA ehash bits) =
        asn1Container Sequence [pkalg,OID eOid] ++ [BitString $ toBitArray bits 0]
      where
        eOid = case ehash of
                    ECDSA_Hash_SHA384 -> [1,3,132,0,34]
    encodeInner (PubKeyDH _) = undefined
    encodeInner (PubKeyUnknown _ l) =
        asn1Container Sequence [pkalg,Null] ++ [BitString $ toBitArray l 0]
