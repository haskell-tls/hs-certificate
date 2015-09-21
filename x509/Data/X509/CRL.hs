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
{-# LANGUAGE FlexibleContexts #-}

module Data.X509.CRL
    ( CRL(..)
    , RevokedCertificate(..)
    ) where

import Control.Applicative

import Data.Hourglass (DateTime, TimezoneOffset(..))
import Data.ASN1.Types

import Data.X509.DistinguishedName
import Data.X509.AlgorithmIdentifier
import Data.X509.ExtensionRaw
import Data.X509.Internal

-- | Describe a Certificate revocation list
data CRL = CRL
    { crlVersion             :: Integer
    , crlSignatureAlg        :: SignatureALG
    , crlIssuer              :: DistinguishedName
    , crlThisUpdate          :: DateTime
    , crlNextUpdate          :: Maybe DateTime
    , crlRevokedCertificates :: [RevokedCertificate]
    , crlExtensions          :: Extensions
    } deriving (Show,Eq)

-- | Describe a revoked certificate identifiable by serial number.
data RevokedCertificate = RevokedCertificate
    { revokedSerialNumber :: Integer
    , revokedDate         :: DateTime
    , revokedExtensions   :: Extensions
    } deriving (Show,Eq)

instance ASN1Object CRL where
    toASN1 crl = encodeCRL crl
    fromASN1 = runParseASN1State parseCRL

-- TODO support extension
instance ASN1Object RevokedCertificate where
    fromASN1 (Start Sequence : IntVal serial : ASN1Time _ t _ : End Sequence : xs) =
        Right (RevokedCertificate serial t (Extensions Nothing), xs)
    fromASN1 l = Left ("fromASN1: X509.RevokedCertificate: unknown format:" ++ show l)
    toASN1 (RevokedCertificate serial time _) = \xs ->
        Start Sequence : IntVal serial : ASN1Time TimeGeneralized time (Just (TimezoneOffset 0)) : End Sequence : xs

parseCRL :: ParseASN1 CRL
parseCRL = do
    CRL <$> (getNext >>= getVersion)
        <*> getObject
        <*> getObject
        <*> (getNext >>= getThisUpdate)
        <*> getNextUpdate
        <*> getRevokedCertificates
        <*> getObject
  where getVersion (IntVal v) = return $ fromIntegral v
        getVersion _          = throwParseError "unexpected type for version"

        getThisUpdate (ASN1Time _ t1 _) = return t1
        getThisUpdate _                 = throwParseError "bad this update format, expecting time"

        getNextUpdate = getNextMaybe timeOrNothing

        timeOrNothing (ASN1Time _ tnext _) = Just tnext
        timeOrNothing _                    = Nothing

        getRevokedCertificates = onNextContainer Sequence $ getMany getObject

encodeCRL :: CRL -> ASN1S
encodeCRL crl xs =
    [IntVal $ crlVersion crl] ++
    toASN1 (crlSignatureAlg crl) [] ++
    toASN1 (crlIssuer crl) [] ++
    [ASN1Time TimeGeneralized (crlThisUpdate crl) (Just (TimezoneOffset 0))] ++
    (maybe [] (\t -> [ASN1Time TimeGeneralized t (Just (TimezoneOffset 0))]) (crlNextUpdate crl)) ++
    [Start Sequence] ++
    revoked ++
    [End Sequence] ++
    toASN1 (crlExtensions crl) [] ++
    xs
  where
    revoked = concatMap (\e -> toASN1 e []) (crlRevokedCertificates crl)
