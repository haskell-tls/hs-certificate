-- |
-- Module      : Data.X509.Validation
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Certificate checks and validations routines
--
-- Follows RFC5280 / RFC6818
--
module Data.X509.Validation
    (
    ) where

import Data.X509
import Data.Time.Clock

import Data.X509.Validation.Signature

data FailedReason =
      UnknownCriticalExtension -- ^ certificate contains an unknown critical extension
    | Expired                  -- ^ validity ends before checking time
    | InFuture                 -- ^ validity starts after checking time
    | SelfSigned               -- ^ certificate is self signed
    | UnknownCA                -- ^ unknown Certificate Authority (CA)
    | NotAllowedToSign         -- ^ certificate is not allowed to sign (not a CA)
    | SignatureFailed          -- ^ signature failed
    | NoCommonName             -- ^ Certificate doesn't have any common name (CN)
    | NameMismatch String      -- ^ connection name and certificate do not match
    | InvalidWildcard          -- ^ invalid wildcard in certificate
    deriving (Show,Eq)

data Checks = Checks
    { checkValidity       :: Bool
    , checkStrictOrdering :: Bool
    } deriving (Show,Eq)

defaultChecks = Checks
    { checkValidity       = True
    , checkStrictOrdering = False
    }

validate :: Checks -> CertificateChain -> IO [FailedReason]
validate checks certificateChain = do
    time <- getCurrentTime
    doCheck 
  where doCheck = return []

-- | Validate that the current time is between validity bounds
validateTime :: UTCTime -> Certificate -> [FailedReason]
validateTime currentTime cert
    | currentTime < before = [InFuture]
    | currentTime > after  = [Expired]
    | otherwise            = []
  where (before, after) = certValidity cert

getNames :: Certificate -> (Maybe String, [String])
getNames cert = (commonName, altNames)
  where commonName = getDnElement DnCommonName $ certSubjectDN cert
        altNames   = maybe [] (maybe [] toAltName . extensionGet) $ certExtensions cert
        toAltName (ExtSubjectAltName names) = names

validateCertificateName :: Certificate -> [FailedReason]
validateCertificateName cert
    | commonName == Nothing = [NoCommonName]
    | otherwise             = []
  where (commonName, altNames) = getNames cert

-- | Validate that the name used to connect to a host
-- match the certificate used.
validateNameMatch :: String -> Certificate -> [FailedReason]
validateNameMatch fqhn cert =
    undefined
{-
    let names = maybe [] ((:[]) . snd) (lookup oidCommonName $ getDistinguishedElements $ certSubjectDN cert)
             ++ maybe [] (maybe [] toAltName . extensionGet) (certExtensions cert) in
    orUsage $ map (matchDomain . splitDot) names
    where
        orUsage [] = undefined--[rejectMisc "FQDN do not match this certificate"
        orUsage (x:xs)
            | x == []   = []
            | otherwise = orUsage xs

        toAltName (ExtSubjectAltName l) = l
        matchDomain l
            | length (filter (== "") l) > 0 = rejectMisc "commonname OID got empty subdomain"
            | head l == "*"                 = wildcardMatch (reverse $ drop 1 l)
            | otherwise                     = if l == splitDot fqhn
                then CertificateUsageAccept
                else rejectMisc "FQDN and common name OID do not match"


        -- only 1 wildcard is valid, and if multiples are present
        -- they won't have a wildcard meaning but will be match as normal star
        -- character to the fqhn and inevitably will fail.
        wildcardMatch l
            -- <star>.com or <star> is always invalid
            | length l < 2                         = [InvalidWildcard]
            --
            | length (head l) <= 2 && length (head $ drop 1 l) <= 3 && length l < 3 = [InvalidWilcard]
            | otherwise                            =
                if l == take (length l) (reverse $ splitDot fqhn)
                    then CertificateUsageAccept
                    else NameMismatchrejectMisc "FQDN and common name OID do not match"

        splitDot :: String -> [String]
        splitDot [] = [""]
        splitDot x  =
            let (y, z) = break (== '.') x in
            y : (if z == "" then [] else splitDot $ drop 1 z)
-}
