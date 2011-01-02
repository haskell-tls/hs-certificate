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

import Data.ASN1.DER (encodeASN1)
import Data.ASN1.BER (decodeASN1)
import Data.ASN1.Types (ASN1t(..))
import qualified Data.ByteString.Lazy as L

data Private = Private
	{ version :: Int
	, priv    :: Integer
	, pub     :: Integer
	, p       :: Integer
	, q       :: Integer
	, g       :: Integer
	}

parsePrivate :: ASN1t -> Either String Private
parsePrivate (Sequence [ IntVal ver, IntVal p_pub, IntVal p_priv, IntVal p_p, IntVal p_g, IntVal p_q ]) =
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
decodePrivate dat = either (Left . show) parsePrivate $ decodeASN1 dat

encodePrivate :: Private -> L.ByteString
encodePrivate pk = encodeASN1 pkseq
	where pkseq = Sequence
		[ IntVal $ fromIntegral $ version pk
		, IntVal $ pub pk
		, IntVal $ priv pk
		, IntVal $ p pk
		, IntVal $ g pk
		, IntVal $ q pk
		]
