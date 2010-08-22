module Data.Certificate.Key (
	PrivateKey(..),
	decodePrivateKey,
	encodePrivateKey
	) where

import Data.ASN1.DER hiding (decodeASN1)
import Data.ASN1.BER (decodeASN1)
import qualified Data.ByteString.Lazy as L

data PrivateKey = PrivateKey
	{ privKey_version :: Int
	, privKey_modulus :: Integer
	, privKey_public_exponant :: Integer
	, privKey_private_exponant :: Integer
	, privKey_p1 :: Integer
	, privKey_p2 :: Integer
	, privKey_exp1 :: Integer
	, privKey_exp2 :: Integer
	, privKey_coef :: Int
	}

parsePrivateKey :: ASN1 -> Either String PrivateKey
parsePrivateKey x =
	case x of
		Sequence [ IntVal ver, IntVal modulus, IntVal pub_exp
		         , IntVal priv_exp, IntVal p1, IntVal p2
		         , IntVal exp1, IntVal exp2, IntVal coef ] ->
			Right $ PrivateKey
				{ privKey_version = fromIntegral ver
				, privKey_modulus = modulus
				, privKey_public_exponant = pub_exp
				, privKey_private_exponant = priv_exp
				, privKey_p1 = p1
				, privKey_p2 = p2
				, privKey_exp1 = exp1
				, privKey_exp2 = exp2
				, privKey_coef = fromIntegral coef }
		_ ->
			Left "unexpected format"

decodePrivateKey :: L.ByteString -> Either String PrivateKey
decodePrivateKey dat = either (Left . show) parsePrivateKey $ decodeASN1 dat

encodePrivateKey :: PrivateKey -> L.ByteString
encodePrivateKey pk = encodeASN1 pkseq
	where
		pkseq = Sequence [ IntVal ver, IntVal modulus, IntVal pub_exp
		                 , IntVal priv_exp, IntVal p1, IntVal p2
		                 , IntVal exp1, IntVal exp2, IntVal coef ]
		ver = fromIntegral $ privKey_version pk
		modulus = privKey_modulus pk
		pub_exp = privKey_public_exponant pk
		priv_exp = privKey_private_exponant pk
		p1 = privKey_p1 pk
		p2 = privKey_p2 pk
		exp1 = privKey_exp1 pk
		exp2 = privKey_exp2 pk
		coef = fromIntegral $ privKey_coef pk
