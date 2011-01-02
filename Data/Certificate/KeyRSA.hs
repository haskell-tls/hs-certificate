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

import Data.ASN1.DER (encodeASN1)
import Data.ASN1.BER (decodeASN1)
import Data.ASN1.Types (ASN1t(..))
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

parsePrivate :: ASN1t -> Either String Private
parsePrivate (Sequence
	[ IntVal ver, IntVal modulus, IntVal pub_exp
	, IntVal priv_exp, IntVal p1, IntVal p2
	, IntVal exp1, IntVal exp2, IntVal coef ]) =
		Right $ Private
			{ version          = fromIntegral ver
			, lenmodulus       = calculate_modulus modulus 1
			, modulus          = modulus
			, public_exponant  = pub_exp
			, private_exponant = priv_exp
			, p1               = p1
			, p2               = p2
			, exp1             = exp1
			, exp2             = exp2
			, coef             = coef
			}
	where
		calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)
parsePrivate _ = Left "unexpected format"

decodePrivate :: L.ByteString -> Either String Private
decodePrivate dat = either (Left . show) parsePrivate $ decodeASN1 dat

encodePrivate :: Private -> L.ByteString
encodePrivate pk = encodeASN1 pkseq
	where pkseq = Sequence
		[ IntVal $ fromIntegral $ version pk
		, IntVal $ modulus pk
		, IntVal $ public_exponant pk
		, IntVal $ private_exponant pk
		, IntVal $ p1 pk
		, IntVal $ p2 pk
		, IntVal $ exp1 pk
		, IntVal $ exp2 pk
		, IntVal $ fromIntegral $ coef pk
		]
