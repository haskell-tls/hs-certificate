-- |
-- Module      : Data.X509
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Read/Write X509 Certificate, CRL and their signed equivalents.
--
-- Follows RFC5280 / RFC6818
--

module Data.X509
        (
        -- * Data Structure
          SignedCertificate(..)
        -- * Data Structure (reexported from X509Cert)
        , SignatureALG(..)
        , HashALG(..)
        , ECDSA_Hash(..)
        , PubKeyALG(..)
        , PubKey(..)
        , OID
        , DistinguishedName(..)
        , Certificate(..)
        , module Data.X509.Ext

        -- * helper for signing/veryfing certificate
        , getSigningData

        -- * serialization from ASN1 bytestring
        , decodeCertificate
        , encodeCertificate

        -- * Distinguished names related function
        , decodeDN
        , encodeDN
        , hashDN
        , hashDN_old
        ) where

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import qualified Data.ASN1.BinaryEncoding.Raw as Raw (toByteString)
import Data.ASN1.Stream
import Data.ASN1.BitArray
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Data.X509.Internal
import Data.X509.Cert hiding (encodeDN)
import qualified  Data.X509.Cert as Cert
import Data.X509.Ext

import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1

data SignedCertificate = SignedCertificate
    { x509Cert              :: Certificate          -- ^ the certificate part of a SignedCertificate structure
    , x509CachedSigningData :: (Maybe B.ByteString) -- ^ a cache of the raw representation of the x509 part for signing
                                                    -- since encoding+decoding might not result in the same data being signed.
    , x509CachedData        :: (Maybe B.ByteString) -- ^ a cache of the raw representation of the whole x509.
    , x509SignatureALG      :: SignatureALG         -- ^ the signature algorithm used.
    , x509Signature         :: B.ByteString         -- ^ the signature.
    } deriving (Show)

instance Eq SignedCertificate where
        x1 == x2 =
                (x509Cert x1         == x509Cert x2)         &&
                (x509SignatureALG x1 == x509SignatureALG x2) &&
                (x509Signature x1    == x509Signature x2)

{- | get signing data related to a SignedCertificate message,
 - which is either the cached data or the encoded certificate -}
getSigningData :: SignedCertificate -> B.ByteString
getSigningData (SignedCertificate _    (Just e) _ _ _) = e
getSigningData (SignedCertificate cert Nothing _ _ _)  = encodeASN1' DER header
        where header    = asn1Container Sequence $ toASN1 cert []

{- | decode an SignedCertificate from a bytestring
 - the structure is the following:
 -   Certificate
 -   Certificate Signature Algorithm
 -   Certificate Signature
-}
decodeCertificate :: B.ByteString -> Either String SignedCertificate
decodeCertificate by = either (Left . show) parseRootASN1 $ decodeASN1Repr' BER by
  where
        {- | parse root structure of a x509 certificate. this has to be a sequence of 3 objects :
         - * the header
         - * the signature algorithm
         - * the signature -}
        parseRootASN1 l = onContainer (fst $ getConstructedEndRepr l) $ \l2 ->
            let (certrepr,rem1)  = getConstructedEndRepr l2
                (sigalgseq,rem2) = getConstructedEndRepr rem1
                (sigseq,_)       = getConstructedEndRepr rem2
                cert             = onContainer certrepr (either Left (Right . fst) . fromASN1 . map fst)
             in case (cert, map fst sigseq) of
                    (Right c, [BitString b]) ->
                        let certevs = Raw.toByteString $ concatMap snd certrepr
                            sigalg  = fromASN1 $ map fst sigalgseq
                         in case sigalg of
                                Left s -> Left ("certificate error: " ++ s)
                                Right (sa,_) -> Right $ SignedCertificate c (Just certevs) (Just by) sa (bitArrayGetData b)
                    (Left err, _) -> Left $ ("certificate error: " ++ show err)
                    _             -> Left $ "certificate structure error"

        onContainer ((Start _, _) : l) f =
            case reverse l of
                ((End _, _) : l2) -> f $ reverse l2
                _                 -> f []
        onContainer _ f = f []

{-| encode a SignedCertificate certificate to a bytestring -}
encodeCertificate :: SignedCertificate -> B.ByteString
encodeCertificate (SignedCertificate _    _ (Just bs) _      _      ) = bs
encodeCertificate (SignedCertificate cert _ Nothing   sigalg sigbits) = encodeASN1' DER rootSeq
        where
                esigalg   = toASN1 sigalg [] -- asn1Container Sequence [OID (sigOID sigalg), Null]
                esig      = BitString $ toBitArray sigbits 0
                header    = asn1Container Sequence $ toASN1 cert []
                rootSeq   = asn1Container Sequence (header ++ esigalg ++ [esig])

decodeDN :: L.ByteString -> Either String DistinguishedName
decodeDN by = either (Left . show) (runParseASN1 parseDN) $ decodeASN1 BER by

encodeDN :: DistinguishedName -> L.ByteString
encodeDN dn = encodeASN1 DER $ Cert.encodeDN dn

-- | Make an openssl style hash of distinguished name
hashDN :: DistinguishedName -> B.ByteString
hashDN = shorten . SHA1.hash . encodeASN1' DER . Cert.encodeDNinner toLowerUTF8
    where toLowerUTF8 (_, s) = (UTF8, B.map asciiToLower s)
          asciiToLower c
            | c >= w8A && c <= w8Z = fromIntegral (fromIntegral c - fromEnum 'A' + fromEnum 'a')
            | otherwise            = c
          w8A = fromIntegral $ fromEnum 'A'
          w8Z = fromIntegral $ fromEnum 'Z'

-- | Create an openssl style old hash of distinguished name
hashDN_old :: DistinguishedName -> B.ByteString
hashDN_old = shorten . MD5.hash . encodeASN1' DER . Cert.encodeDN

shorten :: B.ByteString -> B.ByteString
shorten b = B.pack $ map i [3,2,1,0]
    where i n = B.index b n
