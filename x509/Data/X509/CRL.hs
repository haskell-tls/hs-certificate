-- |
-- Module      : Data.X509.CRL
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Read and Write X509 Certificate Revocation List (CRL).
--
-- follows RFC5280 / RFC6818.
--
module Data.X509.CRL
    ( CRL(..)
    , Extension(..)
    , RevokedCertificate(..)
    ) where

import Data.Time.Clock (UTCTime)
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding

import Data.X509.AlgorithmIdentifier

-- FIXME
type Name = String

-- | Describe a Certificate revocation list
data CRL = CRL
    { crlVersion             :: Integer
    , crlSignatureAlg        :: SignatureALG
    , crlIssuer              :: Name
    , crlThisUpdate          :: UTCTime
    , crlNextUpdate          :: Maybe UTCTime
    , crlRevokedCertificates :: [RevokedCertificate]
    , crlExtensions          :: Maybe [Extension]
    } deriving (Show,Eq)

-- FIXME
data Extension = Extension
    deriving (Show,Eq)

-- | Describe a revoked certificate identifiable by serial number.
data RevokedCertificate = RevokedCertificate
    { revokedSerialNumber :: Integer
    , revokedDate         :: UTCTime
    , revokedExtensions   :: Maybe [Extension]
    } deriving (Show,Eq)

instance ASN1Object CRL where
    toASN1 crl = undefined
    fromASN1 s = undefined
