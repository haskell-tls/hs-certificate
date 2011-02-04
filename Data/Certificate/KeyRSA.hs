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
	( Private(..)
	, decodePrivate
	, encodePrivate
	) where

import Data.ASN1.DER (encodeASN1Stream, ASN1(..), ASN1ConstructionType(..))
import Data.ASN1.BER (decodeASN1Stream)
import qualified Data.ByteString.Lazy as L

data Private = Private
	{ version          :: Int
	, lenmodulus       :: Int
	, modulus          :: Integer
	, public_exponant  :: Integer
	, private_exponant :: Integer
	, p1               :: Integer
	, p2               :: Integer
	, exp1             :: Integer
	, exp2             :: Integer
	, coef             :: Integer
	}

parsePrivate :: [ASN1] -> Either String Private
parsePrivate
	[ Start Sequence
	, IntVal ver, IntVal p_modulus, IntVal pub_exp
	, IntVal priv_exp, IntVal p_p1, IntVal p_p2
	, IntVal p_exp1, IntVal p_exp2, IntVal p_coef
	, End Sequence ] =
		Right $ Private
			{ version          = fromIntegral ver
			, lenmodulus       = calculate_modulus p_modulus 1
			, modulus          = p_modulus
			, public_exponant  = pub_exp
			, private_exponant = priv_exp
			, p1               = p_p1
			, p2               = p_p2
			, exp1             = p_exp1
			, exp2             = p_exp2
			, coef             = p_coef
			}
	where
		calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)
parsePrivate _ = Left "unexpected format"

decodePrivate :: L.ByteString -> Either String Private
decodePrivate dat = either (Left . show) parsePrivate $ decodeASN1Stream dat

encodePrivate :: Private -> L.ByteString
encodePrivate pk =
	case encodeASN1Stream pkseq of
		Left err  -> error $ show err
		Right lbs -> lbs
	where pkseq =
		[ Start Sequence
		, IntVal $ fromIntegral $ version pk
		, IntVal $ modulus pk
		, IntVal $ public_exponant pk
		, IntVal $ private_exponant pk
		, IntVal $ p1 pk
		, IntVal $ p2 pk
		, IntVal $ exp1 pk
		, IntVal $ exp2 pk
		, IntVal $ fromIntegral $ coef pk
		, End Sequence
		]
