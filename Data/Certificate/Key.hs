-- |
-- Module      : Data.Certificate.Key
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Read/Write Private Key
--

module Data.Certificate.Key
	( PrivateRSAKey(..)
	, decodePrivateRSAKey
	, encodePrivateRSAKey
	) where

import Data.ASN1.DER hiding (decodeASN1)
import Data.ASN1.BER (decodeASN1)
import qualified Data.ByteString.Lazy as L

data PrivateRSAKey = PrivateRSAKey
	{ privRSAKey_version          :: Int
	, privRSAKey_lenmodulus       :: Int
	, privRSAKey_modulus          :: Integer
	, privRSAKey_public_exponant  :: Integer
	, privRSAKey_private_exponant :: Integer
	, privRSAKey_p1               :: Integer
	, privRSAKey_p2               :: Integer
	, privRSAKey_exp1             :: Integer
	, privRSAKey_exp2             :: Integer
	, privRSAKey_coef             :: Integer
	}

parsePrivateRSAKey :: ASN1 -> Either String PrivateRSAKey
parsePrivateRSAKey (Sequence
	[ IntVal ver, IntVal modulus, IntVal pub_exp
	, IntVal priv_exp, IntVal p1, IntVal p2
	, IntVal exp1, IntVal exp2, IntVal coef ]) =
		Right $ PrivateRSAKey
			{ privRSAKey_version          = fromIntegral ver
			, privRSAKey_lenmodulus       = calculate_modulus modulus 1
			, privRSAKey_modulus          = modulus
			, privRSAKey_public_exponant  = pub_exp
			, privRSAKey_private_exponant = priv_exp
			, privRSAKey_p1               = p1
			, privRSAKey_p2               = p2
			, privRSAKey_exp1             = exp1
			, privRSAKey_exp2             = exp2
			, privRSAKey_coef             = coef
			}
	where
		calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)

parsePrivateRSAKey _ = Left "unexpected format"

decodePrivateRSAKey :: L.ByteString -> Either String PrivateRSAKey
decodePrivateRSAKey dat = either (Left . show) parsePrivateRSAKey $ decodeASN1 dat

encodePrivateRSAKey :: PrivateRSAKey -> L.ByteString
encodePrivateRSAKey pk = encodeASN1 pkseq
	where
		pkseq    = Sequence [ IntVal ver, IntVal modulus, IntVal pub_exp
		                    , IntVal priv_exp, IntVal p1, IntVal p2
		                    , IntVal exp1, IntVal exp2, IntVal coef ]
		ver      = fromIntegral $ privRSAKey_version pk
		modulus  = privRSAKey_modulus pk
		pub_exp  = privRSAKey_public_exponant pk
		priv_exp = privRSAKey_private_exponant pk
		p1       = privRSAKey_p1 pk
		p2       = privRSAKey_p2 pk
		exp1     = privRSAKey_exp1 pk
		exp2     = privRSAKey_exp2 pk
		coef     = fromIntegral $ privRSAKey_coef pk
