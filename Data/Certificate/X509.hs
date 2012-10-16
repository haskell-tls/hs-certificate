-- |
-- Module      : Data.Certificate.X509
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Read/Write X509 certificate
--

module Data.Certificate.X509
        (
        -- * Data Structure
          X509(..)
        -- * Data Structure (reexported from X509Cert)
        , SignatureALG(..)
        , HashALG(..)
        , PubKeyALG(..)
        , PubKey(..)
        , OID
        , ASN1StringType(..)
        , ASN1String
        , DistinguishedName(..)
        , Certificate(..)
        , module Data.Certificate.X509.Ext

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

import Data.Char
import Data.Word
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import qualified Data.ASN1.BinaryEncoding.Raw as Raw (toLazyByteString)
import Data.ASN1.Stream
import Data.ASN1.BitArray
import Data.ASN1.Object
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Data.Certificate.X509.Internal
import Data.Certificate.X509.Cert hiding (encodeDN)
import qualified  Data.Certificate.X509.Cert as Cert
import Data.Certificate.X509.Ext

import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1

data X509 = X509
        { x509Cert              :: Certificate          -- ^ the certificate part of a X509 structure
        , x509CachedSigningData :: (Maybe L.ByteString) -- ^ a cache of the raw representation of the x509 part for signing
                                                        -- since encoding+decoding might not result in the same data being signed.
        , x509CachedData        :: (Maybe L.ByteString) -- ^ a cache of the raw representation of the whole x509.
        , x509SignatureALG      :: SignatureALG         -- ^ the signature algorithm used.
        , x509Signature         :: [Word8]              -- ^ the signature.
        } deriving (Show)

instance Eq X509 where
        x1 == x2 =
                (x509Cert x1         == x509Cert x2)         &&
                (x509SignatureALG x1 == x509SignatureALG x2) &&
                (x509Signature x1    == x509Signature x2)

{- | get signing data related to a X509 message,
 - which is either the cached data or the encoded certificate -}
getSigningData :: X509 -> L.ByteString
getSigningData (X509 _    (Just e) _ _ _) = e
getSigningData (X509 cert Nothing _ _ _)  = encodeASN1 DER header
        where header    = asn1Container Sequence $ toASN1 cert

{- | decode an X509 from a bytestring
 - the structure is the following:
 -   Certificate
 -   Certificate Signature Algorithm
 -   Certificate Signature
-}
decodeCertificate :: L.ByteString -> Either String X509
decodeCertificate by = either (Left . show) parseRootASN1 $ decodeASN1Repr BER by
        where
                {- | parse root structure of a x509 certificate. this has to be a sequence of 3 objects :
                 - * the header
                 - * the signature algorithm
                 - * the signature -}
                parseRootASN1 l = onContainer (fst $ getConstructedEndRepr l) $ \l2 ->
                                let (certrepr,rem1)  = getConstructedEndRepr l2 in
                                let (sigalgseq,rem2) = getConstructedEndRepr rem1 in
                                let (sigseq,_)       = getConstructedEndRepr rem2 in
                                let cert = onContainer certrepr (either Left (Right . fst) . fromASN1 . map fst) in
                                case (cert, map fst sigseq) of
                                        (Right c, [BitString b]) ->
                                                let certevs = Raw.toLazyByteString $ concatMap snd certrepr in
                                                let sigalg  = onContainer sigalgseq (parseSigAlg . map fst) in
                                                Right $ X509 c (Just certevs) (Just by) sigalg (L.unpack $ bitArrayGetData b)
                                        (Left err, _) -> Left $ ("certificate error: " ++ show err)
                                        _             -> Left $ "certificate structure error"

                onContainer ((Start _, _) : l) f =
                        case reverse l of
                                ((End _, _) : l2) -> f $ reverse l2
                                _                 -> f []
                onContainer _ f = f []

                parseSigAlg [ OID oid, Null ] = oidSig oid
                parseSigAlg _                 = SignatureALG_Unknown []

{-| encode a X509 certificate to a bytestring -}
encodeCertificate :: X509 -> L.ByteString
encodeCertificate (X509 _    _ (Just lbs) _      _      ) = lbs
encodeCertificate (X509 cert _ Nothing    sigalg sigbits) = encodeASN1 DER rootSeq
        where
                esigalg   = asn1Container Sequence [OID (sigOID sigalg), Null]
                esig      = BitString $ toBitArray (L.pack sigbits) 0
                header    = asn1Container Sequence $ toASN1 cert
                rootSeq   = asn1Container Sequence (header ++ esigalg ++ [esig])

decodeDN :: L.ByteString -> Either String DistinguishedName
decodeDN by = either (Left . show) (runParseASN1 parseDN) $ decodeASN1 BER by

encodeDN :: DistinguishedName -> L.ByteString
encodeDN dn = encodeASN1 DER $ Cert.encodeDN dn

-- | Make an openssl style hash of distinguished name
hashDN :: DistinguishedName -> B.ByteString
hashDN = shorten . SHA1.hash . encodeASN1' DER . Cert.encodeDNinner toLowerUTF8
    where toLowerUTF8 (_, s) = (UTF8, map asciiToLower s)
          asciiToLower c
            | c >= 'A' && c <= 'Z' = toLower c
            | otherwise            = c

-- | Create an openssl style old hash of distinguished name
hashDN_old :: DistinguishedName -> B.ByteString
hashDN_old = shorten . MD5.hash . encodeASN1' DER . Cert.encodeDN

shorten :: B.ByteString -> B.ByteString
shorten b = B.pack $ map i [3,2,1,0]
    where i n = B.index b n
