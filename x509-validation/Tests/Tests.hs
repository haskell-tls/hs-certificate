-- | Validation test suite.
module Main (main) where

import Control.Applicative
import Control.Monad (unless)

import Crypto.Hash.Algorithms

import qualified Crypto.PubKey.DSA        as DSA
import qualified Crypto.PubKey.ECC.Types  as ECC
import qualified Crypto.PubKey.RSA.PSS    as PSS

import Data.Default.Class
import Data.Monoid
import Data.String (fromString)
import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation

import Data.Hourglass
import System.Hourglass

import Test.Tasty
import Test.Tasty.HUnit

import Certificate


-- Runtime data, dynamically generated and shared by all test cases --

data RData pub priv = RData
    { rootStore           :: CertificateStore
    , past                :: (DateTime, DateTime)
    , present             :: (DateTime, DateTime)
    , future              :: (DateTime, DateTime)
    , pastDate            :: DateTime
    , presentDate         :: DateTime
    , futureDate          :: DateTime
    , root                :: Pair pub priv
    , intermediate        :: Pair pub priv
    , intermediate0       :: Pair pub priv
    , intermediatePast    :: Pair pub priv
    , intermediateFuture  :: Pair pub priv
    , keys1               :: Keys pub priv
    , keys2               :: Keys pub priv
    , keys3               :: Keys pub priv
    }

mkDateTime :: Date -> DateTime
mkDateTime d = DateTime d (TimeOfDay 0 0 0 0)

mkStore :: [Pair pub priv] -> CertificateStore
mkStore ps = makeCertificateStore (map pairSignedCert ps)

initData :: Alg pub priv -> IO (RData pub priv)
initData alg = do
    today <- timeGetDate <$> timeCurrent

    let m3 = mkDateTime $ today `dateAddPeriod` mempty { periodYears = -3 }
    let m2 = mkDateTime $ today `dateAddPeriod` mempty { periodYears = -2 }
    let m1 = mkDateTime $ today `dateAddPeriod` mempty { periodYears = -1 }
    let n1 = mkDateTime $ today `dateAddPeriod` mempty { periodYears =  1 }
    let n2 = mkDateTime $ today `dateAddPeriod` mempty { periodYears =  2 }
    let n3 = mkDateTime $ today `dateAddPeriod` mempty { periodYears =  3 }

    -- two-year validity periods in past, present and future
    let vPast    = (m3, m1) -- Year-3 .. Year-1
    let vPresent = (m1, n1) -- Year-1 .. Year+1
    let vFuture  = (n1, n3) -- Year+1 .. Year+3

    -- CA basic constraints and key usage extensions
    let bc  = Just $ ExtBasicConstraints True Nothing
    let bc0 = Just $ ExtBasicConstraints True (Just 0)
    let ku  = Nothing

    -- Root CAs in past, present and future.  Need distinct DNs because the
    -- certificate store contains all 3 simultaneously.
    rootPast       <- generateKeys alg >>= mkCA 1  "RootCA - R1"    vPast    bc  ku Self
    rootPresent    <- generateKeys alg >>= mkCA 2  "RootCA - R2"    vPresent bc  ku Self
    rootFuture     <- generateKeys alg >>= mkCA 3  "RootCA - R3"    vFuture  bc  ku Self

    -- Intermediate CAs in past, present and future.  Also includes a CA with
    -- a depth constraint.
    pIntermediateP <- generateKeys alg >>= mkCA 11 "IntermediateCA" vPast    bc  ku (CA rootPast)
    pIntermediate  <- generateKeys alg >>= mkCA 12 "IntermediateCA" vPresent bc  ku (CA rootPresent)
    pIntermediate0 <- generateKeys alg >>= mkCA 12 "IntermediateCA" vPresent bc0 ku (CA rootPresent)
    pIntermediateF <- generateKeys alg >>= mkCA 13 "IntermediateCA" vFuture  bc  ku (CA rootFuture)

    -- Additional keys to be reused in test cases.  This removes the cost of
    -- generating individual keys.  A key should be used only once per case.
    k1 <- generateKeys alg
    k2 <- generateKeys alg
    k3 <- generateKeys alg

    return RData
        { rootStore           = mkStore [ rootPast, rootPresent, rootFuture ]
        , past                = vPast
        , present             = vPresent
        , future              = vFuture
        , pastDate            = m2               -- Year-2
        , presentDate         = mkDateTime today
        , futureDate          = n2               -- Year+2
        , root                = rootPresent
        , intermediate        = pIntermediate
        , intermediate0       = pIntermediate0
        , intermediatePast    = pIntermediateP
        , intermediateFuture  = pIntermediateF
        , keys1               = k1
        , keys2               = k2
        , keys3               = k3
        }

freeData :: RData pub priv -> IO ()
freeData _ = return ()


-- Test utilities --

-- | Asserts order-insensitive equality for lists.  This also ignores
-- duplicate elements.
assertEqualList :: (Eq a, Show a) => String -- ^ The message prefix
                              -> [a]        -- ^ The expected value
                              -> [a]        -- ^ The actual value
                              -> Assertion
assertEqualList preface expected actual =
    unless (actual `same` expected) (assertFailure msg)
 where
    a `same` b = all (`elem` b) a && all (`elem` a) b
    msg = (if null preface then "" else preface ++ "\n") ++
          "    expected: " ++ show expected ++ "\n     but got: " ++ show actual

-- | Asserts the validation result of a certificate chain.
assertValidationResult :: RData pub priv   -- ^ Common test resources (CA store)
                       -> ValidationChecks -- ^ Checks to do
                       -> HostName         -- ^ Connection identification
                       -> [Pair pub priv]  -- ^ Certificate chain to validate
                       -> [FailedReason]   -- ^ Expected validation result
                       -> Assertion
assertValidationResult rd checks hostname ps expected = do
    actual <- validate HashSHA256 defaultHooks checks store def ident chain
    assertEqualList "Unexpected validation result" expected actual
  where
    store = rootStore rd
    ident = (hostname, fromString ":443")
    chain = CertificateChain (map pairSignedCert ps)

-- | Simplified access to test resource from 'withResource'.
testWithRes :: IO r -> TestName -> (r -> Assertion) -> TestTree
testWithRes res caseName f = testCase caseName (res >>= f)


-- Test cases --

-- | Tests a leaf certificate signed by an intermediate CA, but using a chain
-- where the intermediate CA may use a different key.  This tests the signature
-- of the leaf certificate provided both CAs have the same subject DN.
testSignature :: IO (RData pub priv)               -- ^ Common test resources
              -> TestName                          -- ^ Case name
              -> (RData pub priv -> Pair pub priv) -- ^ CA to use for signature
              -> (RData pub priv -> Pair pub priv) -- ^ CA to use for validation
              -> [FailedReason]                    -- ^ Expected validation result
              -> TestTree
testSignature res caseName f g expected = testWithRes res caseName $ \rd -> do
    pair <- mkLeaf "signature" (present rd) (CA $ f rd) (keys1 rd)
    assertValidationResult rd defaultChecks "signature" [pair, g rd] expected

-- | Tests an empty certificate chain.
testEmpty :: IO (RData pub priv) -- ^ Common test resources
          -> TestName            -- ^ Case name
          -> [FailedReason]      -- ^ Expected validation result
          -> TestTree
testEmpty res caseName expected = testWithRes res caseName $ \rd ->
    assertValidationResult rd defaultChecks "empty" [] expected

-- | Tests a certificate chain where the intermediate CA is missing.
testIncompleteChain :: IO (RData pub priv) -- ^ Common test resources
                    -> TestName            -- ^ Case name
                    -> [FailedReason]      -- ^ Expected validation result
                    -> TestTree
testIncompleteChain res caseName expected = testWithRes res caseName $ \rd -> do
    pair <- mkLeaf "incomplete" (present rd) (CA $ intermediate rd) (keys1 rd)
    assertValidationResult rd defaultChecks "incomplete" [pair] expected

-- | Tests a self-signed certificate.
testSelfSigned :: IO (RData pub priv) -- ^ Common test resources
               -> TestName            -- ^ Case name
               -> [FailedReason]      -- ^ Expected validation result
               -> TestTree
testSelfSigned res caseName expected = testWithRes res caseName $ \rd -> do
    pair <- mkLeaf "self-signed" (present rd) Self (keys1 rd)
    assertValidationResult rd defaultChecks "self-signed" [pair] expected

-- | Tests key usage of intermediate CA, with or without 'checkCAConstraints'.
testCAKeyUsage :: IO (RData pub priv) -- ^ Common test resources
               -> TestName            -- ^ Case name
               -> Bool                -- ^ Value for 'checkCAConstraints'
               -> ExtKeyUsageFlag     -- ^ Intermediate CA key usage
               -> [FailedReason]      -- ^ Expected validation result
               -> TestTree
testCAKeyUsage res caseName check flag expected = testWithRes res caseName $ \rd -> do
    ca <- mkCA 20 "KeyUsageCA" (present rd) bc ku (CA $ root rd) (keys1 rd)
    pair <- mkLeaf "ca-key-usage" (present rd) (CA ca) (keys2 rd)
    assertValidationResult rd checks "ca-key-usage" [pair, ca] expected
  where
    checks = defaultChecks { checkCAConstraints = check }
    bc = Just (ExtBasicConstraints True Nothing)
    ku = Just (ExtKeyUsage [flag])

-- | Tests CA flag of intermediate CA, with or without 'checkCAConstraints'.
testNotCA :: IO (RData pub priv) -- ^ Common test resources
          -> TestName            -- ^ Case name
          -> Bool                -- ^ Value for 'checkCAConstraints'
          -> [FailedReason]      -- ^ Expected validation result
          -> TestTree
testNotCA res caseName check expected = testWithRes res caseName $ \rd -> do
    ca <- mkCA 20 "NotCA" (present rd) bc Nothing (CA $ root rd) (keys1 rd)
    pair <- mkLeaf "not-ca" (present rd) (CA ca) (keys2 rd)
    assertValidationResult rd checks "not-ca" [pair, ca] expected
  where
    checks = defaultChecks { checkCAConstraints = check }
    bc = Just (ExtBasicConstraints False Nothing)

-- | Tests an intermediate CA without basic constraints, with or without
-- 'checkCAConstraints'.
testNoBasic :: IO (RData pub priv) -- ^ Common test resources
            -> TestName            -- ^ Case name
            -> Bool                -- ^ Value for 'checkCAConstraints'
            -> [FailedReason]      -- ^ Expected validation result
            -> TestTree
testNoBasic res caseName check expected = testWithRes res caseName $ \rd -> do
    ca <- mkCA 20 "NoBC" (present rd) bc Nothing (CA $ root rd) (keys1 rd)
    pair <- mkLeaf "no-bc" (present rd) (CA ca) (keys2 rd)
    assertValidationResult rd checks "no-bc" [pair, ca] expected
  where
    checks = defaultChecks { checkCAConstraints = check }
    bc = Nothing

-- | Tests basic constraints depth, with or without 'checkCAConstraints'.
testBadDepth :: IO (RData pub priv) -- ^ Common test resources
             -> TestName            -- ^ Case name
             -> Bool                -- ^ Value for 'checkCAConstraints'
             -> [FailedReason]      -- ^ Expected validation result
             -> TestTree
testBadDepth res caseName check expected = testWithRes res caseName $ \rd -> do
    -- a new CA signed by intermediate0 should fail because of the depth limit
    ca <- mkCA 20 "TooDeep" (present rd) bc Nothing (CA $ intermediate0 rd) (keys1 rd)
    pair <- mkLeaf "bad-depth" (present rd) (CA ca) (keys2 rd)
    assertValidationResult rd checks "bad-depth" [pair, ca, intermediate0 rd] expected
  where
    checks = defaultChecks { checkCAConstraints = check }
    bc = Just (ExtBasicConstraints True Nothing)

-- | Tests a non-V3 leaf certificate, with or without 'checkLeafV3'.
testLeafNotV3 :: IO (RData pub priv) -- ^ Common test resources
              -> TestName            -- ^ Case name
              -> Bool                -- ^ Value for 'checkLeafV3'
              -> [FailedReason]      -- ^ Expected validation result
              -> TestTree
testLeafNotV3 res caseName check expected = testWithRes res caseName $ \rd -> do
    pair <- mkCertificate 1 100 dn (present rd) leafStdExts (CA $ intermediate rd) (keys1 rd)
    assertValidationResult rd checks "leaf-not-v3" [pair, intermediate rd] expected
  where
    checks = defaultChecks { checkLeafV3 = check }
    dn = mkDn "leaf-not-v3"

-- | Tests a certificate chain containing a non-related certificate, with or
-- without 'checkStrictOrdering'.
testStrictOrdering :: IO (RData pub priv) -- ^ Common test resources
                   -> TestName            -- ^ Case name
                   -> Bool                -- ^ Value for 'checkStrictOrdering'
                   -> [FailedReason]      -- ^ Expected validation result
                   -> TestTree
testStrictOrdering res caseName check expected = testWithRes res caseName $ \rd -> do
    ca    <- mkCA 20 "CA"    (present rd) bc Nothing (CA $ intermediate rd) (keys1 rd)
    extra <- mkCA 21 "Extra" (present rd) bc Nothing (CA $ intermediate rd) (keys2 rd)
    pair  <- mkLeaf "strict-ordering" (present rd) (CA ca) (keys3 rd)
    assertValidationResult rd checks "strict-ordering" [pair, ca, extra, intermediate rd] expected
  where
    checks = defaultChecks { checkStrictOrdering = check }
    bc = Just (ExtBasicConstraints True Nothing)

-- | Tests validity of leaf certificate.
testLeafDates :: IO (RData pub priv)                      -- ^ Common test resources
              -> TestName                                 -- ^ Case name
              -> Bool                                     -- ^ Value for 'checkTimeValidity'
              -> (RData pub priv -> (DateTime, DateTime)) -- ^ Validity period to use
              -> [FailedReason]                           -- ^ Expected validation result
              -> TestTree
testLeafDates res caseName check f expected = testWithRes res caseName $ \rd -> do
    pair <- mkLeaf "leaf-dates" (f rd) (CA $ intermediate rd) (keys1 rd)
    assertValidationResult rd checks "leaf-dates" [pair, intermediate rd] expected
  where
    checks = defaultChecks { checkTimeValidity = check }

-- | Tests validity of intermediate CA.
testIntermediateDates :: IO (RData pub priv)               -- ^ Common test resources
                      -> TestName                          -- ^ Case name
                      -> Bool                              -- ^ Value for 'checkTimeValidity'
                      -> (RData pub priv -> Pair pub priv) -- ^ Intermediate CA to use
                      -> [FailedReason]                    -- ^ Expected validation result
                      -> TestTree
testIntermediateDates res caseName check f expected = testWithRes res caseName $ \rd -> do
    pair <- mkLeaf "intermediate-dates" (present rd) (CA $ f rd) (keys1 rd)
    assertValidationResult rd checks "intermediate-dates" [pair, f rd] expected
  where
    checks = defaultChecks { checkTimeValidity = check }

-- | Tests validity of leaf certificate and intermediate CA,
-- using 'checkAtTime'.
testTimeshift :: IO (RData pub priv)                      -- ^ Common test resources
              -> TestName                                 -- ^ Case name
              -> (RData pub priv -> (DateTime, DateTime)) -- ^ Leaf validity period
              -> (RData pub priv -> Pair pub priv)        -- ^ Intermediate CA to use
              -> (RData pub priv -> DateTime)             -- ^ Value for 'checkAtTime'
              -> [FailedReason]                           -- ^ Expected validation result
              -> TestTree
testTimeshift res caseName f g h expected = testWithRes res caseName $ \rd -> do
    let checks = defaultChecks { checkAtTime = Just $ h rd }
    pair <- mkLeaf "timeshift" (f rd) (CA $ g rd) (keys1 rd)
    assertValidationResult rd checks "timeshift" [pair, g rd] expected

-- | Tests an empty DistinguishedName.
testNoCommonName :: IO (RData pub priv) -- ^ Common test resources
                 -> TestName            -- ^ Case name
                 -> [FailedReason]      -- ^ Expected validation result
                 -> TestTree
testNoCommonName res caseName expected = testWithRes res caseName $ \rd -> do
    pair <- mkCertificate 2 100 dn (present rd) leafStdExts (CA $ intermediate rd) (keys1 rd)
    assertValidationResult rd defaultChecks "no-cn" [pair, intermediate rd] expected
  where
    dn = DistinguishedName []

-- | Tests certificate CommonName against expected hostname, with or without
-- 'checkFQHN'.
testCommonName :: IO (RData pub priv) -- ^ Common test resources
               -> String              -- ^ Certificate CommonName
               -> HostName            -- ^ Connection identification
               -> Bool                -- ^ Value for 'checkFQHN'
               -> [FailedReason]      -- ^ Expected validation result
               -> TestTree
testCommonName res cn hostname check expected = testWithRes res caseName $ \rd -> do
    pair <- mkLeaf cn (present rd) (CA $ intermediate rd) (keys1 rd)
    assertValidationResult rd checks hostname [pair, intermediate rd] expected
  where
    caseName = if null hostname then "empty" else hostname
    checks = defaultChecks { checkFQHN = check }

-- | Tests certificate SubjectAltName against expected hostname, with or
-- without 'checkFQHN'.
testSubjectAltName :: IO (RData pub priv) -- ^ Common test resources
                   -> String              -- ^ Certificate SubjectAltName
                   -> HostName            -- ^ Connection identification
                   -> Bool                -- ^ Value for 'checkFQHN'
                   -> [FailedReason]      -- ^ Expected validation result
                   -> TestTree
testSubjectAltName res san hostname check expected = testWithRes res caseName $ \rd -> do
    pair <- mkCertificate 2 100 dn (present rd) (ext:leafStdExts) (CA $ intermediate rd) (keys1 rd)
    assertValidationResult rd checks hostname [pair, intermediate rd] expected
  where
    caseName = if null hostname then "empty" else hostname
    checks = defaultChecks { checkFQHN = check }
    dn = mkDn "cn-not-used" -- this CN value is to be tested too
                            -- (to make sure CN is *not* considered when a
                            -- SubjectAltName exists)
    ext = mkExtension False $
            -- wraps test value with other values
            ExtSubjectAltName [ AltNameDNS    "dummy1"
                              , AltNameRFC822 "test@example.com"
                              , AltNameDNS    san
                              , AltNameDNS    "dummy2"
                              ]

-- | Tests 'checkLeafKeyUsage'.
testLeafKeyUsage :: IO (RData pub priv) -- ^ Common test resources
                 -> TestName            -- ^ Case name
                 -> [ExtKeyUsageFlag]   -- ^ Certificate flags
                 -> [ExtKeyUsageFlag]   -- ^ Flags required for validation
                 -> [FailedReason]      -- ^ Expected validation result
                 -> TestTree
testLeafKeyUsage res caseName cFlags vFlags expected = testWithRes res caseName $ \rd -> do
    pair <- mkCertificate 2 100 dn (present rd) exts (CA $ intermediate rd) (keys1 rd)
    assertValidationResult rd checks "key-usage" [pair, intermediate rd] expected
  where
    checks = defaultChecks { checkLeafKeyUsage = vFlags }
    dn = mkDn "key-usage"
    exts = if null cFlags then [] else [mkExtension False (ExtKeyUsage cFlags)]

-- | Tests 'checkLeafKeyPurpose'.
testLeafKeyPurpose :: IO (RData pub priv)  -- ^ Common test resources
                   -> TestName             -- ^ Case name
                   -> [ExtKeyUsagePurpose] -- ^ Certificate flags
                   -> [ExtKeyUsagePurpose] -- ^ Flags required for validation
                   -> [FailedReason]       -- ^ Expected validation result
                   -> TestTree
testLeafKeyPurpose res caseName cFlags vFlags expected = testWithRes res caseName $ \rd -> do
    pair <- mkCertificate 2 100 dn (present rd) exts (CA $ intermediate rd) (keys1 rd)
    assertValidationResult rd checks "key-purpose" [pair, intermediate rd] expected
  where
    checks = defaultChecks { checkLeafKeyPurpose = vFlags }
    dn = mkDn "key-purpose"
    exts = if null cFlags then [] else [mkExtension False (ExtExtendedKeyUsage cFlags)]

-- | Tests validation with multiple failure reasons in exhaustive mode.
testExhaustive :: IO (RData pub priv) -- ^ Common test resources
               -> String              -- ^ Certificate CommonName
               -> HostName            -- ^ Connection identification
               -> [FailedReason]      -- ^ Expected validation result
               -> TestTree
testExhaustive res cn hostname expected = testWithRes res caseName $ \rd -> do
    -- build an expired self-signed certificate with an invalid signature:
    -- the certificate is actually signed by a clone using a different key
    p1 <- mkLeaf cn (past rd) Self    (keys1 rd)
    p2 <- mkLeaf cn (past rd) (CA p1) (keys2 rd)
    assertValidationResult rd checks hostname [p2] expected
  where
    caseName = if null hostname then "empty" else hostname
    checks = defaultChecks { checkExhaustive = True }


-- | All validation test cases.
treeWithAlg :: TestName -> Alg pub priv -> TestTree
treeWithAlg groupName alg = withResource (initData alg) freeData $ \res ->
    testGroup groupName
      [ testGroup "signature"
          [ testSignature res "valid"   intermediate intermediate  []
          , testSignature res "invalid" intermediate intermediate0 [InvalidSignature SignatureInvalid]
          ]
      , testGroup "chain"
          [ testEmpty           res "empty"       [EmptyChain]
          , testIncompleteChain res "incomplete"  [UnknownCA]
          , testSelfSigned      res "self-signed" [SelfSigned]
          , testGroup "leaf-not-v3"
              [ testLeafNotV3       res "v3-disallowed" True  [LeafNotV3]
              , testLeafNotV3       res "v3-allowed"    False []
              ]
          , testGroup "strict-ordering"
              [ testStrictOrdering  res "enabled"  True  [UnknownCA]
              , testStrictOrdering  res "disabled" False []
              ]
          ]
      , testGroup "ca-constraints"
          [ testGroup "enabled"
              [ testCAKeyUsage res "cert-sign" True  KeyUsage_keyCertSign []
              , testCAKeyUsage res "crl-sign"  True  KeyUsage_cRLSign     [NotAllowedToSign]
              , testNotCA      res "not-ca"    True                       [NotAnAuthority]
              , testNoBasic    res "no-basic"  True                       [NotAnAuthority]
              , testBadDepth   res "bad-depth" True                       [AuthorityTooDeep]
              ]
          , testGroup "disabled"
              [ testCAKeyUsage res "cert-sign" False KeyUsage_keyCertSign []
              , testCAKeyUsage res "crl-sign"  False KeyUsage_cRLSign     []
              , testNotCA      res "not-ca"    False                      []
              , testNoBasic    res "no-basic"  False                      []
              , testBadDepth   res "bad-depth" False                      []
              ]
          ]
      , testGroup "dates"
          [ testGroup "leaf"
              [ testGroup "enabled"
                  [ testLeafDates res "past"    True  past    [Expired]
                  , testLeafDates res "present" True  present []
                  , testLeafDates res "future"  True  future  [InFuture]
                  ]
              , testGroup "disabled"
                  [ testLeafDates res "past"    False past    []
                  , testLeafDates res "present" False present []
                  , testLeafDates res "future"  False future  []
                  ]
              ]
          , testGroup "intermediate"
              [ testGroup "enabled"
                  [ testIntermediateDates res "past"    True  intermediatePast    [Expired]
                  , testIntermediateDates res "present" True  intermediate        []
                  , testIntermediateDates res "future"  True  intermediateFuture  [InFuture]
                  ]
              , testGroup "disabled"
                  [ testIntermediateDates res "past"    False intermediatePast    []
                  , testIntermediateDates res "present" False intermediate        []
                  , testIntermediateDates res "future"  False intermediateFuture  []
                  ]
              ]
          , testGroup "timeshift"
              [ testGroup "at-past"
                  [ testTimeshift res "past"    past    intermediatePast    pastDate    []
                  , testTimeshift res "present" present intermediate        pastDate    [InFuture]
                  , testTimeshift res "future"  future  intermediateFuture  pastDate    [InFuture]
                  ]
              , testGroup "at-present"
                  [ testTimeshift res "past"    past    intermediatePast    presentDate [Expired]
                  , testTimeshift res "present" present intermediate        presentDate []
                  , testTimeshift res "future"  future  intermediateFuture  presentDate [InFuture]
                  ]
              , testGroup "in-future"
                  [ testTimeshift res "past"    past    intermediatePast    futureDate  [Expired]
                  , testTimeshift res "present" present intermediate        futureDate  [Expired]
                  , testTimeshift res "future"  future  intermediateFuture  futureDate  []
                  ]
              ]
          ]
      , testGroup "CommonName"
          [ testNoCommonName res "no-common-name" [NoCommonName]
          , testGroup "simple"
              [ testCommonName res "www.example.com"  "www.example.com"  True []
              , testCommonName res "www.example.com"  "www2.example.com" True [NameMismatch "www2.example.com"]
              , testCommonName res "www.example.com"  "WWW.EXAMPLE.COM"  True []
              , testCommonName res "www.example.com"  "www.EXAMPLE.COM"  True []
              , testCommonName res "www.example.com"  "WWW.example.com"  True []
              , testCommonName res "www..example.com" "www..example.com" True [NameMismatch "www..example.com"] -- InvalidName "www..example.com"
              , testCommonName res ""                 ""                 True [NameMismatch ""] -- InvalidName ""
              ]
          , testGroup "wildcard"
              [ testCommonName res "*.example.com" "example.com"       True [NameMismatch "example.com"]
              , testCommonName res "*.example.com" "www.example.com"   True []
              , testCommonName res "*.example.com" "www.EXAMPLE.com"   True []
              , testCommonName res "*.example.com" "www2.example.com"  True []
              , testCommonName res "*.example.com" "www.m.example.com" True [NameMismatch "www.m.example.com"]
              , testCommonName res "*"             "single"            True [NameMismatch "single"] -- InvalidWildcard
              ]
          , testGroup "disabled"
              [ testCommonName res "www.example.com"  "www.example.com"  False []
              , testCommonName res "www.example.com"  "www2.example.com" False []
              , testCommonName res "www.example.com"  "WWW.EXAMPLE.COM"  False []
              , testCommonName res "www.example.com"  "www.EXAMPLE.COM"  False []
              , testCommonName res "www.example.com"  "WWW.example.com"  False []
              , testCommonName res "www..example.com" "www..example.com" False []
              , testCommonName res ""                 ""                 False []
              ]
          ]
      , testGroup "SubjectAltName"
          [ testGroup "simple"
              [ testSubjectAltName res "www.example.com"  "www.example.com"  True []
              , testSubjectAltName res "www.example.com"  "www2.example.com" True [NameMismatch "www2.example.com"]
              , testSubjectAltName res "www.example.com"  "WWW.EXAMPLE.COM"  True []
              , testSubjectAltName res "www.example.com"  "www.EXAMPLE.COM"  True []
              , testSubjectAltName res "www.example.com"  "WWW.example.com"  True []
              , testSubjectAltName res "www..example.com" "www..example.com" True [NameMismatch "www..example.com"] -- InvalidName "www..example.com"
              , testSubjectAltName res ""                 ""                 True [NameMismatch ""] -- InvalidName ""
              ]
          , testGroup "wildcard"
              [ testSubjectAltName res "*.example.com" "example.com"       True [NameMismatch "example.com"]
              , testSubjectAltName res "*.example.com" "www.example.com"   True []
              , testSubjectAltName res "*.example.com" "www.EXAMPLE.com"   True []
              , testSubjectAltName res "*.example.com" "www2.example.com"  True []
              , testSubjectAltName res "*.example.com" "www.m.example.com" True [NameMismatch "www.m.example.com"]
              , testSubjectAltName res "*"             "single"            True [NameMismatch "single"] -- InvalidWildcard
              ]
          , testSubjectAltName res "www.example.com"  "cn-not-used" True [NameMismatch "cn-not-used"]
          , testGroup "disabled"
              [ testSubjectAltName res "www.example.com"  "www.example.com"  False []
              , testSubjectAltName res "www.example.com"  "www2.example.com" False []
              , testSubjectAltName res "www.example.com"  "WWW.EXAMPLE.COM"  False []
              , testSubjectAltName res "www.example.com"  "www.EXAMPLE.COM"  False []
              , testSubjectAltName res "www.example.com"  "WWW.example.com"  False []
              , testSubjectAltName res "www..example.com" "www..example.com" False []
              , testSubjectAltName res ""                 ""                 False []
              ]
          ]
      , testGroup "key-usage"
          [ testLeafKeyUsage res "none"    []           [u2, u3] []
          , testLeafKeyUsage res "valid"   [u1, u2, u3] [u2, u3] []
          , testLeafKeyUsage res "invalid" [u1, u3]     [u2, u3] [LeafKeyUsageNotAllowed]
          ]
      , testGroup "key-purpose"
          [ testLeafKeyPurpose res "none"    []           [p2, p3] []
          , testLeafKeyPurpose res "valid"   [p1, p2, p3] [p2, p3] []
          , testLeafKeyPurpose res "invalid" [p1, p3]     [p2, p3] [LeafKeyPurposeNotAllowed]
          ]
      , testExhaustive res "exhaustive2" "exhaustive"
          [ SelfSigned
          , Expired
          , InvalidSignature SignatureInvalid
          , NameMismatch "exhaustive"
          ]
      ]
  where
    (u1, u2, u3) = (KeyUsage_keyEncipherment, KeyUsage_dataEncipherment, KeyUsage_keyAgreement)
    (p1, p2, p3) = (KeyUsagePurpose_ClientAuth, KeyUsagePurpose_CodeSigning, KeyUsagePurpose_EmailProtection)

-- | Runs the test suite.
main :: IO ()
main = defaultMain $ testGroup "Validation"
    [ treeWithAlg "RSA"    (AlgRSA    2048           hashSHA256)
    , treeWithAlg "RSAPSS" (AlgRSAPSS 2048 pssParams hashSHA224)
    , treeWithAlg "DSA"    (AlgDSA    dsaParams      hashSHA1)
    , treeWithAlg "ECDSA"  (AlgEC     curveName      hashSHA512)
    , treeWithAlg "Ed25519" AlgEd25519
    , treeWithAlg "Ed448"   AlgEd448
    ]
  where
    pssParams = PSS.defaultPSSParams SHA224
    -- DSA parameters were generated using 'openssl dsaparam -C 2048'
    dsaParams = DSA.Params
        { DSA.params_p = 0x9994B9B1FC22EC3A5F607B5130D314F35FC8D387015A6D8FA2B56D3CC1F13FE330A631DBC765CEFFD6986BDEB8512580BBAD93D56EE7A8997DB9C65C29313FBC5077DB6F1E9D9E6D3499F997F09C8CF8ECC9E5F38DC34C3D656CFDF463893DDF9E246E223D7E5C4E86F54426DDA5DE112FCEDBFB5B6D6F7C76ED190EA1A7761CA561E8E5803F9D616DAFF25E2CCD4011A6D78D5CE8ED28CC2D865C7EC01508BA96FBD1F8BB5E517B6A5208A90AC2D3DCAE50281C02510B86C16D449465CD4B3754FD91AA19031282122A25C68292F033091FCB9DEBDE0D220F81F7EE4AB6581D24BE48204AF3DA52BDB944DA53B76148055395B30954735DC911574D360C953B
        , DSA.params_g = 0x10E51AEA37880C5E52DD477ED599D55050C47012D038B9E4B3199C9DE9A5B873B1ABC8B954F26AFEA6C028BCE1783CFE19A88C64E4ED6BFD638802A78457A5C25ABEA98BE9C6EF18A95504C324315EABE7C1EA50E754591E3EFD3D33D4AE47F82F8978ABC871C135133767ACC60683F065430C749C43893D73596B12D5835A78778D0140B2F63B32A5658308DD5BA6BBC49CF6692929FA6A966419404F9A2C216860E3F339EDDB49AD32C294BDB4C9C6BB0D1CC7B691C65968C3A0A5106291CD3810147C8A16B4BFE22968AD9D3890733F4AA9ACD8687A5B981653A4B1824004639956E8C1EDAF31A8224191E8ABD645D2901F5B164B4B93F98039A6EAEC6088
        , DSA.params_q = 0xE1FDFADD32F46B5035EEB3DB81F9974FBCA69BE2223E62FCA8C77989B2AACDF7
        }
    curveName = ECC.SEC_p384r1
