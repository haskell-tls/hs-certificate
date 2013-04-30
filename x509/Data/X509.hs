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
    -- * Types
      SignedCertificate
    , SignedCRL
    , Certificate(..)
    , DistinguishedName(..)
    , PubKey(..)
    , module Data.X509.CertificateChain
    , module Data.X509.AlgorithmIdentifier
    , module Data.X509.Ext

    -- * Signed types and marshalling
    , Signed(..)
    , SignedExact
    , getSigned
    , getSignedData
    , objectToSignedExact
    , encodeSignedObject
    , decodeSignedObject

    -- * Hash distinguished names related function
    , hashDN
    , hashDN_old
    ) where

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import qualified Data.ByteString as B

import Data.X509.Cert
import Data.X509.Ext
import Data.X509.CRL
import Data.X509.CertificateChain
import Data.X509.DistinguishedName
import Data.X509.Signed
import Data.X509.PublicKey
import Data.X509.AlgorithmIdentifier

import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1

type SignedCertificate = SignedExact Certificate
type SignedCRL         = SignedExact CRL

-- | Make an OpenSSL style hash of distinguished name
--
-- OpenSSL algorithm is odd, and has been replicated here somewhat.
-- only lower the case of ascii character.
hashDN :: DistinguishedName -> B.ByteString
hashDN = shorten . SHA1.hash . encodeASN1' DER . flip toASN1 [] . DistinguishedNameInner . dnLowerUTF8
    where dnLowerUTF8 (DistinguishedName l) = DistinguishedName $ map toLowerUTF8 l
          toLowerUTF8 (oid, (_, s)) = (oid, (UTF8, B.map asciiToLower s))
          asciiToLower c
            | c >= w8A && c <= w8Z = fromIntegral (fromIntegral c - fromEnum 'A' + fromEnum 'a')
            | otherwise            = c
          w8A = fromIntegral $ fromEnum 'A'
          w8Z = fromIntegral $ fromEnum 'Z'

-- | Create an openssl style old hash of distinguished name
hashDN_old :: DistinguishedName -> B.ByteString
hashDN_old = shorten . MD5.hash . encodeASN1' DER . flip toASN1 []

shorten :: B.ByteString -> B.ByteString
shorten b = B.pack $ map i [3,2,1,0]
    where i n = B.index b n
