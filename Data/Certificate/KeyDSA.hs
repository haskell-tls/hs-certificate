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
        ( decodePrivate
        , encodePrivate
        ) where

import Data.ASN1.DER (encodeASN1Stream, ASN1(..), ASN1ConstructionType(..))
import Data.ASN1.BER (decodeASN1Stream)
import qualified Data.ByteString.Lazy as L
import qualified Crypto.Types.PubKey.DSA as DSA

parsePrivate :: [ASN1] -> Either String (DSA.PublicKey, DSA.PrivateKey)
parsePrivate
        [ Start Sequence
        , IntVal 0, IntVal pub, IntVal priv, IntVal p, IntVal g, IntVal q
        , End Sequence ] = Right (pubkey, privkey)
    where
        privkey = DSA.PrivateKey { DSA.private_params = params, DSA.private_x = priv }
        pubkey  = DSA.PublicKey { DSA.public_params = params, DSA.public_y = pub }
        params  = (p,g,q)

parsePrivate (Start Sequence : IntVal n : _)
        | n == 0    = Left "DSA key format: not recognized"
        | otherwise = Left ("DSA key format: unknown version " ++ show n)
parsePrivate _ = Left "unexpected format"

decodePrivate :: L.ByteString -> Either String (DSA.PublicKey, DSA.PrivateKey)
decodePrivate dat = either (Left . show) parsePrivate $ decodeASN1Stream dat

encodePrivate :: (DSA.PublicKey, DSA.PrivateKey) -> L.ByteString
encodePrivate (pubkey, privkey) =
        case encodeASN1Stream pkseq of
                Left err  -> error $ show err
                Right lbs -> lbs
        where pkseq =
                [ Start Sequence
                , IntVal 0
                , IntVal $ DSA.public_y pubkey
                , IntVal $ DSA.private_x privkey
                , IntVal p
                , IntVal g
                , IntVal q
                , End Sequence
                ]
              (p,g,q) = DSA.private_params privkey
