module Data.X509.PublicKey where

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray

import Data.X509.Internal

import qualified Crypto.Types.PubKey.RSA as RSA
import qualified Crypto.Types.PubKey.DSA as DSA
import Data.Word

import qualified Data.ByteString as B

data PubKeyALG =
      PubKeyALG_RSA
    | PubKeyALG_DSA
    | PubKeyALG_ECDSA
    | PubKeyALG_DH
    | PubKeyALG_Unknown OID
    deriving (Show,Eq)

knownPubkeyAlgs =
    [ PubKeyALG_RSA
    , PubKeyALG_DSA
    , PubKeyALG_ECDSA
    , PubKeyALG_DH
    ]

data ECDSA_Hash = ECDSA_Hash_SHA384
                deriving (Show,Eq)

data PubKey =
          PubKeyRSA RSA.PublicKey -- ^ RSA public key
        | PubKeyDSA DSA.PublicKey -- ^ DSA public key
        | PubKeyDH (Integer,Integer,Integer,Maybe Integer,([Word8], Integer))
                                    -- ^ DH format with (p,g,q,j,(seed,pgenCounter))
        | PubKeyECDSA ECDSA_Hash B.ByteString -- ^ ECDSA format not done yet FIXME
        | PubKeyUnknown OID [Word8] -- ^ unrecognized format
        deriving (Show,Eq)

instance ObjectIdable PubKeyALG where
    getObjectID PubKeyALG_RSA   = [1,2,840,113549,1,1,1]
    getObjectID PubKeyALG_DSA   = [1,2,840,10040,4,1]
    getObjectID PubKeyALG_ECDSA = [1,2,840,10045,2,1]
    getObjectID PubKeyALG_DH    = [1,2,840,10046,2,1]
    getObjectID (PubKeyALG_Unknown oid) = oid

pk_table :: [ (OID, PubKeyALG) ]
pk_table =
        [ ([1,2,840,113549,1,1,1], PubKeyALG_RSA)
        , ([1,2,840,10040,4,1],    PubKeyALG_DSA)
        , ([1,2,840,10045,2,1],    PubKeyALG_ECDSA)
        , ([1,2,840,10046,2,1],    PubKeyALG_DH)
        ]

instance ASN1Object PubKey where
    fromASN1 (Start Sequence: OID pkalg:xs)
        | pkalg == getObjectID PubKeyALG_RSA =
            case xs of
                End Sequence:BitString bits:xs2 -> decodeASN1Err "RSA" bits xs2 fromASN1
                _ -> Left "fromASN1: X509.PubKey: unknown RSA format"
        | pkalg == getObjectID PubKeyALG_DSA   = undefined
        | pkalg == getObjectID PubKeyALG_ECDSA = undefined
        | otherwise = undefined
        where decodeASN1Err format bits xs2 f =
                case decodeASN1' BER (bitArrayGetData bits) of
                    Left err -> Left ("fromASN1: X509.PubKey " ++ format ++ " bitarray cannot be parsed: " ++ show err)
                    Right s  -> case f s of
                                    Left err -> Left err
                                    Right (r, xsinner) -> Right (r, xsinner ++ xs2)
            
    fromASN1 _ = Left "fromASN1: X509.PubKey: unknown format"
    toASN1 a = \xs -> encodePK a ++ xs

pubkeyToAlg :: PubKey -> PubKeyALG
pubkeyToAlg (PubKeyRSA _)         = PubKeyALG_RSA
pubkeyToAlg (PubKeyDSA _)         = PubKeyALG_DSA
pubkeyToAlg (PubKeyDH _)          = PubKeyALG_DH
pubkeyToAlg (PubKeyECDSA _ _)     = PubKeyALG_ECDSA
pubkeyToAlg (PubKeyUnknown oid _) = PubKeyALG_Unknown oid

encodePK :: PubKey -> [ASN1]
encodePK k@(PubKeyRSA pubkey) =
        asn1Container Sequence (asn1Container Sequence [pkalg,Null] ++ [BitString $ toBitArray bits 0])
        where
                pkalg = OID $ getObjectID $ pubkeyToAlg k
                bits  = encodeASN1' DER $ asn1Container Sequence [IntVal (RSA.public_n pubkey), IntVal (RSA.public_e pubkey)]

encodePK k@(PubKeyDSA pubkey) =
        asn1Container Sequence (asn1Container Sequence ([pkalg] ++ dsaseq) ++ [BitString $ toBitArray bits 0])
        where
                pkalg   = OID $ getObjectID $ pubkeyToAlg k
                dsaseq  = asn1Container Sequence [IntVal (DSA.params_p params)
                                                 ,IntVal (DSA.params_q params)
                                                 ,IntVal (DSA.params_g params)]
                params  = DSA.public_params pubkey
                bits    = encodeASN1' DER [IntVal $ DSA.public_y pubkey]

encodePK k@(PubKeyUnknown _ l) =
        asn1Container Sequence (asn1Container Sequence [pkalg,Null] ++ [BitString $ toBitArray (B.pack l) 0])
        where
                pkalg = OID $ getObjectID $ pubkeyToAlg k

