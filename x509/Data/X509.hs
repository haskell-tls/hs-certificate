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
    , PubKey(..)
    , PubKeyEC(..)
    , SerializedPoint(..)
    , PrivKey(..)
    , PrivKeyEC(..)
    , pubkeyToAlg
    , privkeyToAlg
    , module Data.X509.AlgorithmIdentifier
    , module Data.X509.Ext
    , module Data.X509.ExtensionRaw

    -- * Certificate Revocation List (CRL)
    , module Data.X509.CRL

    -- * Naming
    , DistinguishedName(..)
    , DnElement(..)
    , ASN1CharacterString(..)
    , getDnElement

    -- * Certificate Chain
    , module Data.X509.CertificateChain

    -- * Signed types and marshalling
    , Signed(..)
    , SignedExact
    , getSigned
    , getSignedData
    , objectToSignedExact
    , objectToSignedExactF
    , encodeSignedObject
    , decodeSignedObject

    -- * Parametrized Signed accessor
    , getCertificate
    , getCRL
    , decodeSignedCertificate
    , decodeSignedCRL

    -- * Hash distinguished names related function
    , hashDN
    , hashDN_old
    ) where

import Control.Arrow (second)

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import qualified Data.ByteString as B
import qualified Data.ByteArray as BA

import Data.X509.Cert
import Data.X509.Ext
import Data.X509.ExtensionRaw
import Data.X509.CRL
import Data.X509.CertificateChain
import Data.X509.DistinguishedName
import Data.X509.Signed
import Data.X509.PublicKey
import Data.X509.PrivateKey
import Data.X509.AlgorithmIdentifier

import Crypto.Hash

-- | A Signed Certificate
type SignedCertificate = SignedExact Certificate

-- | A Signed CRL
type SignedCRL         = SignedExact CRL

-- | Get the Certificate associated to a SignedCertificate
getCertificate :: SignedCertificate -> Certificate
getCertificate = signedObject . getSigned

-- | Get the CRL associated to a SignedCRL
getCRL :: SignedCRL -> CRL
getCRL = signedObject . getSigned

-- | Try to decode a bytestring to a SignedCertificate
decodeSignedCertificate :: B.ByteString -> Either String SignedCertificate
decodeSignedCertificate = decodeSignedObject

-- | Try to decode a bytestring to a SignedCRL
decodeSignedCRL :: B.ByteString -> Either String SignedCRL
decodeSignedCRL = decodeSignedObject

-- | Make an OpenSSL style hash of distinguished name
--
-- OpenSSL algorithm is odd, and has been replicated here somewhat.
-- only lower the case of ascii character.
hashDN :: DistinguishedName -> B.ByteString
hashDN = shorten . hashWith SHA1 . encodeASN1' DER . flip toASN1 [] . DistinguishedNameInner . dnLowerUTF8
    where dnLowerUTF8 (DistinguishedName l) = DistinguishedName $ map (second toLowerUTF8) l
          toLowerUTF8 (ASN1CharacterString _ s) = ASN1CharacterString UTF8 (B.map asciiToLower s)
          asciiToLower c
            | c >= w8A && c <= w8Z = fromIntegral (fromIntegral c - fromEnum 'A' + fromEnum 'a')
            | otherwise            = c
          w8A = fromIntegral $ fromEnum 'A'
          w8Z = fromIntegral $ fromEnum 'Z'

-- | Create an openssl style old hash of distinguished name
hashDN_old :: DistinguishedName -> B.ByteString
hashDN_old = shorten . hashWith MD5 . encodeASN1' DER . flip toASN1 []

shorten :: Digest a -> B.ByteString
shorten b = B.pack $ map i [3,2,1,0]
    where i n = BA.index b n
