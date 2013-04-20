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

import Data.ASN1.Stream
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import qualified Data.ByteString.Lazy as L
import qualified Crypto.Types.PubKey.DSA as DSA

parsePrivate :: [ASN1] -> Either String (DSA.PublicKey, DSA.PrivateKey)
parsePrivate
        [ Start Sequence
        , IntVal 0, IntVal p, IntVal q, IntVal g, IntVal pub, IntVal priv
        , End Sequence ] = Right (pubkey, privkey)
    where
        privkey = DSA.PrivateKey { DSA.private_params = params, DSA.private_x = priv }
        pubkey  = DSA.PublicKey { DSA.public_params = params, DSA.public_y = pub }
        params  = DSA.Params { DSA.params_p = p, DSA.params_g = g, DSA.params_q = q }

parsePrivate (Start Sequence : IntVal n : _)
        | n == 0    = Left "DSA key format: not recognized"
        | otherwise = Left ("DSA key format: unknown version " ++ show n)
parsePrivate _ = Left "unexpected format"

decodePrivate :: L.ByteString -> Either String (DSA.PublicKey, DSA.PrivateKey)
decodePrivate dat = either (Left . show) parsePrivate $ decodeASN1 BER dat

encodePrivate :: (DSA.PublicKey, DSA.PrivateKey) -> L.ByteString
encodePrivate (pubkey, privkey) = encodeASN1 DER pkseq
        where pkseq =
                [ Start Sequence
                , IntVal 0
                , IntVal $ DSA.params_p params
                , IntVal $ DSA.params_q params
                , IntVal $ DSA.params_g params
                , IntVal $ DSA.public_y pubkey
                , IntVal $ DSA.private_x privkey
                , End Sequence
                ]
              params = DSA.private_params privkey
