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
      module Data.X509.Validation.Types
    , Fingerprint(..)
    -- * Failed validation types
    , FailedReason(..)
    , SignatureFailure(..)
    -- * Validation configuration types
    , ValidationChecks(..)
    , ValidationHooks(..)
    , defaultChecks
    , defaultHooks
    -- * Validation
    , validate
    , validatePure
    , validateDefault
    , getFingerprint
    -- * Cache
    , module Data.X509.Validation.Cache
    -- * Signature verification
    , module Data.X509.Validation.Signature
    ) where

import Control.Applicative
import Control.Monad (when)
import Data.Default.Class
import Data.ASN1.Types
import Data.Char (toLower)
import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation.Signature
import Data.X509.Validation.Fingerprint
import Data.X509.Validation.Cache
import Data.X509.Validation.Types
import Data.Hourglass
import System.Hourglass
import Data.Maybe
import Data.List

-- | Possible reason of certificate and chain failure.
--
-- The values 'InvalidName' and 'InvalidWildcard' are internal-only and are
-- never returned by the validation functions.  'NameMismatch' is returned
-- instead.
data FailedReason =
      UnknownCriticalExtension -- ^ certificate contains an unknown critical extension
    | Expired                  -- ^ validity ends before checking time
    | InFuture                 -- ^ validity starts after checking time
    | SelfSigned               -- ^ certificate is self signed
    | UnknownCA                -- ^ unknown Certificate Authority (CA)
    | NotAllowedToSign         -- ^ certificate is not allowed to sign
    | NotAnAuthority           -- ^ not a CA
    | AuthorityTooDeep         -- ^ Violation of the optional Basic constraint's path length
    | NoCommonName             -- ^ Certificate doesn't have any common name (CN)
    | InvalidName String       -- ^ Invalid name in certificate
    | NameMismatch String      -- ^ connection name and certificate do not match
    | InvalidWildcard          -- ^ invalid wildcard in certificate
    | LeafKeyUsageNotAllowed   -- ^ the requested key usage is not compatible with the leaf certificate's key usage
    | LeafKeyPurposeNotAllowed -- ^ the requested key purpose is not compatible with the leaf certificate's extended key usage
    | LeafNotV3                -- ^ Only authorized an X509.V3 certificate as leaf certificate.
    | EmptyChain               -- ^ empty chain of certificate
    | CacheSaysNo String       -- ^ the cache explicitely denied this certificate
    | InvalidSignature SignatureFailure -- ^ signature failed
    deriving (Show,Eq)

-- | A set of checks to activate or parametrize to perform on certificates.
--
-- It's recommended to use 'defaultChecks' to create the structure,
-- to better cope with future changes or expansion of the structure.
data ValidationChecks = ValidationChecks
    {
    -- | check time validity of every certificate in the chain.
    -- the make sure that current time is between each validity bounds
    -- in the certificate
      checkTimeValidity   :: Bool
    -- | The time when the validity check happens. When set to Nothing,
    -- the current time will be used
    , checkAtTime         :: Maybe DateTime
    -- | Check that no certificate is included that shouldn't be included.
    -- unfortunately despite the specification violation, a lots of
    -- real world server serves useless and usually old certificates
    -- that are not relevant to the certificate sent, in their chain.
    , checkStrictOrdering :: Bool
    -- | Check that signing certificate got the CA basic constraint.
    -- this is absolutely not recommended to turn it off.
    , checkCAConstraints  :: Bool
    -- | Check the whole certificate chain without stopping at the first failure.
    -- Allow gathering a exhaustive list of failure reasons. if this is
    -- turn off, it's absolutely not safe to ignore a failed reason even it doesn't look serious
    -- (e.g. Expired) as other more serious checks would not have been performed.
    , checkExhaustive     :: Bool
    -- | Check that the leaf certificate is version 3. If disable, version 2 certificate
    -- is authorized in leaf position and key usage cannot be checked.
    , checkLeafV3         :: Bool
    -- | Check that the leaf certificate is authorized to be used for certain usage.
    -- If set to empty list no check are performed, otherwise all the flags is the list
    -- need to exists in the key usage extension. If the extension is not present,
    -- the check will pass and behave as if the certificate key is not restricted to
    -- any specific usage.
    , checkLeafKeyUsage   :: [ExtKeyUsageFlag]
    -- | Check that the leaf certificate is authorized to be used for certain purpose.
    -- If set to empty list no check are performed, otherwise all the flags is the list
    -- need to exists in the extended key usage extension if present. If the extension is not
    -- present, then the check will pass and behave as if the certificate is not restricted
    -- to any specific purpose.
    , checkLeafKeyPurpose :: [ExtKeyUsagePurpose]
    -- | Check the top certificate names matching the fully qualified hostname (FQHN).
    -- it's not recommended to turn this check off, if no other name checks are performed.
    , checkFQHN           :: Bool
    } deriving (Show,Eq)

-- | A set of hooks to manipulate the way the verification works.
--
-- BEWARE, it's easy to change behavior leading to compromised security.
data ValidationHooks = ValidationHooks
    {
    -- | check whether a given issuer 'DistinguishedName' matches the subject
    -- 'DistinguishedName' of a candidate issuer certificate.
      hookMatchSubjectIssuer :: DistinguishedName -> Certificate -> Bool
    -- | check whether the certificate in the second argument is valid at the
    -- time provided in the first argument.  Return an empty list for success
    -- or else one or more failure reasons.
    , hookValidateTime       :: DateTime -> Certificate -> [FailedReason]
    -- | validate the certificate leaf name with the DNS named used to connect
    , hookValidateName       :: HostName -> Certificate -> [FailedReason]
    -- | user filter to modify the list of failure reasons
    , hookFilterReason       :: [FailedReason] -> [FailedReason]
    }

-- | Default checks to perform
--
-- The default checks are:
-- * Each certificate time is valid
-- * CA constraints is enforced for signing certificate
-- * Leaf certificate is X.509 v3
-- * Check that the FQHN match
defaultChecks :: ValidationChecks
defaultChecks = ValidationChecks
    { checkTimeValidity   = True
    , checkAtTime         = Nothing
    , checkStrictOrdering = False
    , checkCAConstraints  = True
    , checkExhaustive     = False
    , checkLeafV3         = True
    , checkLeafKeyUsage   = []
    , checkLeafKeyPurpose = []
    , checkFQHN           = True
    }

instance Default ValidationChecks where
    def = defaultChecks

-- | Default hooks in the validation process
defaultHooks :: ValidationHooks
defaultHooks = ValidationHooks
    { hookMatchSubjectIssuer = matchSI
    , hookValidateTime       = validateTime
    , hookValidateName       = validateCertificateName
    , hookFilterReason       = id
    }

instance Default ValidationHooks where
    def = defaultHooks

-- | Validate using the default hooks and checks and the SHA256 mechanism as hashing mechanism
validateDefault :: CertificateStore  -- ^ The trusted certificate store for CA
                -> ValidationCache   -- ^ the validation cache callbacks
                -> ServiceID         -- ^ identification of the connection
                -> CertificateChain  -- ^ the certificate chain we want to validate
                -> IO [FailedReason] -- ^ the return failed reasons (empty list is no failure)
validateDefault = validate HashSHA256 defaultHooks defaultChecks

-- | X509 validation
--
-- the function first interrogate the cache and if the validation fail,
-- proper verification is done. If the verification pass, the
-- add to cache callback is called.
validate :: HashALG           -- ^ the hash algorithm we want to use for hashing the leaf certificate
         -> ValidationHooks   -- ^ Hooks to use
         -> ValidationChecks  -- ^ Checks to do
         -> CertificateStore  -- ^ The trusted certificate store for CA
         -> ValidationCache   -- ^ the validation cache callbacks
         -> ServiceID         -- ^ identification of the connection
         -> CertificateChain  -- ^ the certificate chain we want to validate
         -> IO [FailedReason] -- ^ the return failed reasons (empty list is no failure)
validate _ _ _ _ _ _ (CertificateChain []) = return [EmptyChain]
validate hashAlg hooks checks store cache ident cc@(CertificateChain (top:_)) = do
    cacheResult <- (cacheQuery cache) ident fingerPrint (getCertificate top)
    case cacheResult of
        ValidationCachePass     -> return []
        ValidationCacheDenied s -> return [CacheSaysNo s]
        ValidationCacheUnknown  -> do
            validationTime <- maybe (timeConvert <$> timeCurrent) return $ checkAtTime checks
            let failedReasons = validatePure validationTime hooks checks store ident cc
            when (null failedReasons) $ (cacheAdd cache) ident fingerPrint (getCertificate top)
            return failedReasons
  where fingerPrint = getFingerprint top hashAlg


-- | Validate a certificate chain with explicit pure parameters
validatePure :: DateTime         -- ^ The time for which to check validity for
             -> ValidationHooks  -- ^ Hooks to use
             -> ValidationChecks -- ^ Checks to do
             -> CertificateStore -- ^ The trusted certificate store for CA
             -> ServiceID        -- ^ Identification of the connection
             -> CertificateChain -- ^ The certificate chain we want to validate
             -> [FailedReason]   -- ^ the return failed reasons (empty list is no failure)
validatePure _              _     _      _     _        (CertificateChain [])           = [EmptyChain]
validatePure validationTime hooks checks store (fqhn,_) (CertificateChain (top:rchain)) =
   hookFilterReason hooks (doLeafChecks |> doCheckChain 0 top rchain)
  where isExhaustive = checkExhaustive checks
        a |> b = exhaustive isExhaustive a b

        doLeafChecks = doNameCheck top ++ doV3Check topCert ++ doKeyUsageCheck topCert
            where topCert = getCertificate top

        doCheckChain :: Int -> SignedCertificate -> [SignedCertificate] -> [FailedReason]
        doCheckChain level current chain =
            doCheckCertificate (getCertificate current)
            -- check if we have a trusted certificate in the store belonging to this issuer.
            |> (case findCertificate (certIssuerDN cert) store of
                Just trustedSignedCert      -> checkSignature current trustedSignedCert
                Nothing | isSelfSigned cert -> [SelfSigned] |> checkSignature current current
                        | null chain        -> [UnknownCA]
                        | otherwise         ->
                            case findIssuer (certIssuerDN cert) chain of
                                Nothing                  -> [UnknownCA]
                                Just (issuer, remaining) ->
                                    checkCA level (getCertificate issuer)
                                    |> checkSignature current issuer
                                    |> doCheckChain (level+1) issuer remaining)
          where cert = getCertificate current
        -- in a strict ordering check the next certificate has to be the issuer.
        -- otherwise we dynamically reorder the chain to have the necessary certificate
        findIssuer issuerDN chain
            | checkStrictOrdering checks =
                case chain of
                    []     -> error "not possible"
                    (c:cs) | matchSubjectIdentifier issuerDN (getCertificate c) -> Just (c, cs)
                           | otherwise                                          -> Nothing
            | otherwise =
                (\x -> (x, filter (/= x) chain)) `fmap` find (matchSubjectIdentifier issuerDN . getCertificate) chain
        matchSubjectIdentifier = hookMatchSubjectIssuer hooks

        -- we check here that the certificate is allowed to be a certificate
        -- authority, by checking the BasicConstraint extension. We also check,
        -- if present the key usage extension for ability to cert sign. If this
        -- extension is not present, then according to RFC 5280, it's safe to
        -- assume that only cert sign (and crl sign) are allowed by this certificate.
        checkCA :: Int -> Certificate -> [FailedReason]
        checkCA level cert
            | not (checkCAConstraints checks)          = []
            | and [allowedSign,allowedCA,allowedDepth] = []
            | otherwise = (if allowedSign then [] else [NotAllowedToSign])
                       ++ (if allowedCA   then [] else [NotAnAuthority])
                       ++ (if allowedDepth then [] else [AuthorityTooDeep])
          where extensions  = certExtensions cert
                allowedSign = case extensionGet extensions of
                                Just (ExtKeyUsage flags) -> KeyUsage_keyCertSign `elem` flags
                                Nothing                  -> True
                (allowedCA,pathLen) = case extensionGet extensions of
                                Just (ExtBasicConstraints True pl) -> (True, pl)
                                _                                  -> (False, Nothing)
                allowedDepth = case pathLen of
                                    Nothing                            -> True
                                    Just pl | fromIntegral pl >= level -> True
                                            | otherwise                -> False

        doNameCheck cert
            | not (checkFQHN checks) = []
            | otherwise              = (hookValidateName hooks) fqhn (getCertificate cert)

        doV3Check cert
            | checkLeafV3 checks = case certVersion cert of
                                        2 {- confusingly it means X509.V3 -} -> []
                                        _ -> [LeafNotV3]
            | otherwise = []

        doKeyUsageCheck cert =
               compareListIfExistAndNotNull mflags (checkLeafKeyUsage checks) LeafKeyUsageNotAllowed
            ++ compareListIfExistAndNotNull mpurposes (checkLeafKeyPurpose checks) LeafKeyPurposeNotAllowed
          where mflags = case extensionGet $ certExtensions cert of
                            Just (ExtKeyUsage keyflags) -> Just keyflags
                            Nothing                     -> Nothing
                mpurposes = case extensionGet $ certExtensions cert of
                            Just (ExtExtendedKeyUsage keyPurposes) -> Just keyPurposes
                            Nothing                                -> Nothing
                -- compare a list of things to an expected list. the expected list
                -- need to be a subset of the list (if not Nothing), and is not will
                -- return [err]
                compareListIfExistAndNotNull Nothing     _        _   = []
                compareListIfExistAndNotNull (Just list) expected err
                    | null expected                       = []
                    | intersect expected list == expected = []
                    | otherwise                           = [err]

        doCheckCertificate cert =
            exhaustiveList (checkExhaustive checks)
                [ (checkTimeValidity checks, hookValidateTime hooks validationTime cert)
                ]
        isSelfSigned :: Certificate -> Bool
        isSelfSigned cert = certSubjectDN cert == certIssuerDN cert

        -- check signature of 'signedCert' against the 'signingCert'
        checkSignature signedCert signingCert =
            case verifySignedSignature signedCert (certPubKey $ getCertificate signingCert) of
                SignaturePass     -> []
                SignatureFailed r -> [InvalidSignature r]

-- | Validate that the current time is between validity bounds
validateTime :: DateTime -> Certificate -> [FailedReason]
validateTime currentTime cert
    | currentTime < before = [InFuture]
    | currentTime > after  = [Expired]
    | otherwise            = []
  where (before, after) = certValidity cert

getNames :: Certificate -> (Maybe String, [String])
getNames cert = (commonName >>= asn1CharacterToString, altNames)
  where commonName = getDnElement DnCommonName $ certSubjectDN cert
        altNames   = maybe [] toAltName $ extensionGet $ certExtensions cert
        toAltName (ExtSubjectAltName names) = catMaybes $ map unAltName names
            where unAltName (AltNameDNS s) = Just s
                  unAltName _              = Nothing

-- | Validate that the fqhn is matched by at least one name in the certificate.
-- If the subjectAltname extension is present, then the certificate commonName
-- is ignored, and only the DNS names, if any, in the subjectAltName are
-- considered.  Otherwise, the commonName from the subjectDN is used.
--
-- Note that DNS names in the subjectAltName are in IDNA A-label form. If the
-- destination hostname is a UTF-8 name, it must be provided to the TLS context
-- in (non-transitional) IDNA2008 A-label form.
validateCertificateName :: HostName -> Certificate -> [FailedReason]
validateCertificateName fqhn cert
    | not $ null altNames =
        findMatch [] $ map matchDomain altNames
    | otherwise =
        case commonName of
            Nothing -> [NoCommonName]
            Just cn -> findMatch [] $ [matchDomain cn]
  where (commonName, altNames) = getNames cert

        findMatch :: [FailedReason] -> [[FailedReason]] -> [FailedReason]
        findMatch _   []      = [NameMismatch fqhn]
        findMatch _   ([]:_)  = []
        findMatch acc (_ :xs) = findMatch acc xs

        matchDomain :: String -> [FailedReason]
        matchDomain name = case splitDot name of
            l | any (== "") l       -> [InvalidName name]
              | head l == "*"       -> wildcardMatch (drop 1 l)
              | l == splitDot fqhn  -> [] -- success: we got a match
              | otherwise           -> [NameMismatch fqhn]

        -- A wildcard matches a single domain name component.
        --
        -- e.g. *.server.com will match www.server.com but not www.m.server.com
        --
        -- Only 1 wildcard is valid and only for the left-most component. If
        -- used at other positions or if multiples are present
        -- they won't have a wildcard meaning but will be match as normal star
        -- character to the fqhn and inevitably will fail.
        --
        -- e.g. *.*.server.com will try to litteraly match the '*' subdomain of server.com
        --
        -- Also '*' is not accepted as a valid wildcard
        wildcardMatch l
            | null l                      = [InvalidWildcard] -- '*' is always invalid
            | l == drop 1 (splitDot fqhn) = [] -- success: we got a match
            | otherwise                   = [NameMismatch fqhn]

        splitDot :: String -> [String]
        splitDot [] = [""]
        splitDot x  =
            let (y, z) = break (== '.') x in
            map toLower y : (if z == "" then [] else splitDot $ drop 1 z)


-- | return true if the 'subject' certificate's issuer match
-- the 'issuer' certificate's subject
matchSI :: DistinguishedName -> Certificate -> Bool
matchSI issuerDN issuer = certSubjectDN issuer == issuerDN

exhaustive :: Bool -> [FailedReason] -> [FailedReason] -> [FailedReason]
exhaustive isExhaustive l1 l2
  | null l1      = l2
  | isExhaustive = l1 ++ l2
  | otherwise    = l1

exhaustiveList :: Bool -> [(Bool, [FailedReason])] -> [FailedReason]
exhaustiveList _            []                    = []
exhaustiveList isExhaustive ((performCheck,c):cs)
    | performCheck = exhaustive isExhaustive c (exhaustiveList isExhaustive cs)
    | otherwise    = exhaustiveList isExhaustive cs
