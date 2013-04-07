-- |
-- Module      : Data.Certificate.Key
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Read\/Write Private\/Public RSA Key
--

module Data.Certificate.KeyRSA
        ( decodePublic
        , decodePrivate
        , encodePublic
        , encodePrivate
        , parse_RSA
        ) where

import Data.ASN1.Stream
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
import qualified Data.ByteString.Lazy as L
import qualified Crypto.Types.PubKey.RSA as RSA

parsePublic :: [ASN1] -> Either String RSA.PublicKey
parsePublic
        [ Start Sequence
        , Start Sequence
        , OID [1,2,840,113549,1,1,1] -- PubKeyALG_RSA
        , Null
        , End Sequence
        , BitString (BitArray _ as1n)
        , End Sequence ] = parse_RSA as1n
parsePublic _ = Left "unexpected format"

decodePublic :: L.ByteString -> Either String RSA.PublicKey
decodePublic dat = either (Left . show) parsePublic $ decodeASN1 BER dat

encodePublic :: RSA.PublicKey -> L.ByteString
encodePublic p = encodeASN1 DER
                [ Start Sequence
                , Start Sequence
                , OID [1,2,840,113549,1,1,1] -- PubKeyALG_RSA
                , Null
                , End Sequence
                , BitString $ toBitArray innerSeq 0
                , End Sequence ]
    where innerSeq = encodeASN1 DER [ Start Sequence
                                    , IntVal $ RSA.public_n p
                                    , IntVal $ RSA.public_e p
                                    , End Sequence
                                    ]

parsePrivate :: [ASN1] -> Either String (RSA.PublicKey, RSA.PrivateKey)
parsePrivate
        [ Start Sequence
        , IntVal 0, IntVal p_modulus, IntVal pub_exp
        , IntVal priv_exp, IntVal p_p1, IntVal p_p2
        , IntVal p_exp1, IntVal p_exp2, IntVal p_coef
        , End Sequence ] = Right (pubkey, privkey)
        where
                privkey = RSA.PrivateKey
                        { RSA.private_pub  = pubkey
                        , RSA.private_d    = priv_exp
                        , RSA.private_p    = p_p1
                        , RSA.private_q    = p_p2
                        , RSA.private_dP   = p_exp1
                        , RSA.private_dQ   = p_exp2
                        , RSA.private_qinv = p_coef
                        }
                pubkey = RSA.PublicKey
                        { RSA.public_size = calculate_modulus p_modulus 1
                        , RSA.public_n    = p_modulus
                        , RSA.public_e    = pub_exp
                        }
                calculate_modulus n i = if (2 ^ (i * 8)) > n
                        then i
                        else calculate_modulus n (i+1)
parsePrivate (Start Sequence : IntVal n : _)
        | n == 0    = Left "RSA key format: not recognized"
        | otherwise = Left ("RSA key format: unknown version " ++ show n)
parsePrivate _ = Left "unexpected format"

decodePrivate :: L.ByteString -> Either String (RSA.PublicKey, RSA.PrivateKey)
decodePrivate dat = either (Left . show) parsePrivate $ decodeASN1 BER dat

encodePrivate :: (RSA.PublicKey, RSA.PrivateKey) -> L.ByteString
encodePrivate (pubkey, privkey) = encodeASN1 DER pkseq
        where pkseq =
                [ Start Sequence
                , IntVal 0
                , IntVal $ RSA.private_n privkey
                , IntVal $ RSA.public_e pubkey
                , IntVal $ RSA.private_d privkey
                , IntVal $ RSA.private_p privkey
                , IntVal $ RSA.private_q privkey
                , IntVal $ RSA.private_dP privkey
                , IntVal $ RSA.private_dQ privkey
                , IntVal $ fromIntegral $ RSA.private_qinv privkey
                , End Sequence
                ]

{- | parse a RSA pubkeys from ASN1 encoded bits.
 - return RSA.PublicKey (len-modulus, modulus, e) if successful -}
parse_RSA :: L.ByteString -> Either String RSA.PublicKey
parse_RSA bits =
        case decodeASN1 BER bits of
                Right [Start Sequence, IntVal modulus, IntVal pubexp, End Sequence] ->
                        Right $ RSA.PublicKey
                                { RSA.public_size = calculate_modulus modulus 1
                                , RSA.public_n    = modulus
                                , RSA.public_e    = pubexp
                                }
                _ -> Left "bad RSA format"
        where
                calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)
