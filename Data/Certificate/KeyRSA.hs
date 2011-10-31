-- |
-- Module      : Data.Certificate.Key
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Read/Write Private RSA Key
--

module Data.Certificate.KeyRSA
	( decodePrivate
	, encodePrivate
	) where

import Data.ASN1.DER (encodeASN1Stream, ASN1(..), ASN1ConstructionType(..))
import Data.ASN1.BER (decodeASN1Stream)
import qualified Data.ByteString.Lazy as L
import qualified Crypto.Types.PubKey.RSA as RSA

parsePrivate :: [ASN1] -> Either String (RSA.PublicKey, RSA.PrivateKey)
parsePrivate
	[ Start Sequence
	, IntVal 0, IntVal p_modulus, IntVal pub_exp
	, IntVal priv_exp, IntVal p_p1, IntVal p_p2
	, IntVal p_exp1, IntVal p_exp2, IntVal p_coef
	, End Sequence ] = Right (pubkey, privkey)
	where
		privkey = RSA.PrivateKey
			{ RSA.private_size = calculate_modulus p_modulus 1
			, RSA.private_n    = p_modulus
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
decodePrivate dat = either (Left . show) parsePrivate $ decodeASN1Stream dat

encodePrivate :: (RSA.PublicKey, RSA.PrivateKey) -> L.ByteString
encodePrivate (pubkey, privkey) =
	case encodeASN1Stream pkseq of
		Left err  -> error $ show err
		Right lbs -> lbs
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
