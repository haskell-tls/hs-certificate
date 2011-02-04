-- |
-- Module      : Data.Certificate.Key
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Read/Write Private Key
--

module Data.Certificate.KeyDSA
	( Private(..)
	, decodePrivate
	, encodePrivate
	) where

import Data.ASN1.DER (encodeASN1Stream, ASN1(..), ASN1ConstructionType(..))
import Data.ASN1.BER (decodeASN1Stream)
import qualified Data.ByteString.Lazy as L

data Private = Private
	{ version :: Int
	, priv    :: Integer
	, pub     :: Integer
	, p       :: Integer
	, q       :: Integer
	, g       :: Integer
	}

parsePrivate :: [ASN1] -> Either String Private
parsePrivate
	[ Start Sequence
	, IntVal ver, IntVal p_pub, IntVal p_priv, IntVal p_p, IntVal p_g, IntVal p_q
	, End Sequence ] =
		Right $ Private
			{ version = fromIntegral ver
			, priv    = p_priv
			, pub     = p_pub
			, p       = p_p
			, q       = p_q
			, g       = p_g
			}

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
		, IntVal $ pub pk
		, IntVal $ priv pk
		, IntVal $ p pk
		, IntVal $ g pk
		, IntVal $ q pk
		, End Sequence
		]
