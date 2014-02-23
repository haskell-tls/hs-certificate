-- |
-- Module      : Data.X509.Ext
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- extension processing module.
--
module Data.X509.Ext
    ( Extension(..)
    -- * Common extension usually found in x509v3
    , ExtBasicConstraints(..)
    , ExtKeyUsage(..)
    , ExtKeyUsageFlag(..)
    , ExtExtendedKeyUsage(..)
    , ExtKeyUsagePurpose(..)
    , ExtSubjectKeyId(..)
    , ExtSubjectAltName(..)
    , ExtAuthorityKeyId(..)
    , ExtCrlDistributionPoints(..)
    , AltName(..)
    , DistributionPoint(..)
    , ReasonFlag(..)
    -- * Accessor turning extension into a specific one
    , extensionGet
    , extensionDecode
    , extensionEncode
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.ASN1.Types
import Data.ASN1.Parse
import Data.ASN1.BitArray
import Data.List (find)
import Data.X509.ExtensionRaw
import Data.X509.DistinguishedName
import Control.Applicative
import Control.Monad.Error

-- | key usage flag that is found in the key usage extension field.
data ExtKeyUsageFlag =
      KeyUsage_digitalSignature -- (0)
    | KeyUsage_nonRepudiation   -- (1) recent X.509 ver have renamed this bit to contentCommitment
    | KeyUsage_keyEncipherment  -- (2)
    | KeyUsage_dataEncipherment -- (3)
    | KeyUsage_keyAgreement     -- (4)
    | KeyUsage_keyCertSign      -- (5)
    | KeyUsage_cRLSign          -- (6)
    | KeyUsage_encipherOnly     -- (7)
    | KeyUsage_decipherOnly     -- (8)
    deriving (Show,Eq,Ord,Enum)

{-
-- RFC 5280
oidDistributionPoints, oidPolicies, oidPoliciesMapping :: OID
oidPolicies           = [2,5,29,32]
oidPoliciesMapping    = [2,5,29,33]
-}

-- | Extension class.
--
-- each extension have a unique OID associated, and a way
-- to encode and decode an ASN1 stream.
class Extension a where
    extOID    :: a -> OID
    extEncode :: a -> [ASN1]
    extDecode :: [ASN1] -> Either String a

-- | Get a specific extension from a lists of raw extensions
extensionGet :: Extension a => Extensions -> Maybe a
extensionGet (Extensions Nothing)  = Nothing
extensionGet (Extensions (Just l)) = findExt l
  where findExt []     = Nothing
        findExt (x:xs) = case extensionDecode x of
                            Just (Right e) -> Just e
                            _              -> findExt xs

-- | Try to decode an ExtensionRaw.
--
-- If this function return:
-- * Nothing, the OID doesn't match
-- * Just Left, the OID matched, but the extension couldn't be decoded
-- * Just Right, the OID matched, and the extension has been succesfully decoded
extensionDecode :: Extension a => ExtensionRaw -> Maybe (Either String a)
extensionDecode = doDecode undefined
  where doDecode :: Extension a => a -> ExtensionRaw -> Maybe (Either String a)
        doDecode dummy (ExtensionRaw oid _ asn1)
            | extOID dummy == oid = Just (extDecode asn1)
            | otherwise           = Nothing

-- | Encode an Extension to extensionRaw
extensionEncode :: Extension a => Bool -> a -> ExtensionRaw
extensionEncode critical ext = ExtensionRaw (extOID ext) critical (extEncode ext)

-- | Basic Constraints
data ExtBasicConstraints = ExtBasicConstraints Bool (Maybe Integer)
    deriving (Show,Eq)

instance Extension ExtBasicConstraints where
    extOID = const [2,5,29,19]
    extEncode (ExtBasicConstraints b Nothing)  = [Start Sequence,Boolean b,End Sequence]
    extEncode (ExtBasicConstraints b (Just i)) = [Start Sequence,Boolean b,IntVal i,End Sequence]

    extDecode [Start Sequence,Boolean b,IntVal v,End Sequence]
        | v >= 0    = Right (ExtBasicConstraints b (Just v))
        | otherwise = Left "invalid pathlen"
    extDecode [Start Sequence,Boolean b,End Sequence] = Right (ExtBasicConstraints b Nothing)
    extDecode [Start Sequence,End Sequence] = Right (ExtBasicConstraints False Nothing)
    extDecode _ = Left "unknown sequence"

-- | Describe key usage
data ExtKeyUsage = ExtKeyUsage [ExtKeyUsageFlag]
    deriving (Show,Eq)

instance Extension ExtKeyUsage where
    extOID = const [2,5,29,15]
    extEncode (ExtKeyUsage flags) = [BitString $ flagsToBits flags]
    extDecode [BitString bits] = Right $ ExtKeyUsage $ bitsToFlags bits
    extDecode _ = Left "unknown sequence"

-- | Key usage purposes for the ExtendedKeyUsage extension
data ExtKeyUsagePurpose =
      KeyUsagePurpose_ServerAuth
    | KeyUsagePurpose_ClientAuth
    | KeyUsagePurpose_CodeSigning
    | KeyUsagePurpose_EmailProtection
    | KeyUsagePurpose_TimeStamping
    | KeyUsagePurpose_OCSPSigning
    | KeyUsagePurpose_Unknown OID
    deriving (Show,Eq,Ord)

extKeyUsagePurposedOID :: [(OID, ExtKeyUsagePurpose)]
extKeyUsagePurposedOID =
    [(keyUsagePurposePrefix 1, KeyUsagePurpose_ServerAuth)
    ,(keyUsagePurposePrefix 2, KeyUsagePurpose_ClientAuth)
    ,(keyUsagePurposePrefix 3, KeyUsagePurpose_CodeSigning)
    ,(keyUsagePurposePrefix 4, KeyUsagePurpose_EmailProtection)
    ,(keyUsagePurposePrefix 8, KeyUsagePurpose_TimeStamping)
    ,(keyUsagePurposePrefix 9, KeyUsagePurpose_OCSPSigning)]
  where keyUsagePurposePrefix r = [1,3,6,1,5,5,7,3,r]

-- | Extended key usage extension
data ExtExtendedKeyUsage = ExtExtendedKeyUsage [ExtKeyUsagePurpose]
    deriving (Show,Eq)

instance Extension ExtExtendedKeyUsage where
    extOID = const [2,5,29,37]
    extEncode (ExtExtendedKeyUsage purposes) =
        [Start Sequence] ++ map (OID . lookupRev) purposes ++ [End Sequence]
      where lookupRev (KeyUsagePurpose_Unknown oid) = oid
            lookupRev kup = maybe (error "unknown key usage purpose") fst $ find ((==) kup . snd) extKeyUsagePurposedOID
    extDecode l = ExtExtendedKeyUsage `fmap` (flip runParseASN1 l $ onNextContainer Sequence $ getMany $ do
        n <- getNext
        case n of
            OID o -> return $ maybe (KeyUsagePurpose_Unknown o) id $ lookup o extKeyUsagePurposedOID
            _     -> error "invalid content in extended key usage")

-- | Provide a way to identify a public key by a short hash.
data ExtSubjectKeyId = ExtSubjectKeyId B.ByteString
    deriving (Show,Eq)

instance Extension ExtSubjectKeyId where
    extOID = const [2,5,29,14]
    extEncode (ExtSubjectKeyId o) = [OctetString o]
    extDecode [OctetString o] = Right $ ExtSubjectKeyId o
    extDecode _ = Left "unknown sequence"

-- | Different naming scheme use by the extension.
--
-- Not all name types are available, missing:
-- otherName
-- x400Address
-- directoryName
-- ediPartyName
-- registeredID
--
data AltName =
      AltNameRFC822 String
    | AltNameDNS String
    | AltNameURI String
    | AltNameIP  B.ByteString
    deriving (Show,Eq,Ord)

-- | Provide a way to supply alternate name that can be
-- used for matching host name.
data ExtSubjectAltName = ExtSubjectAltName [AltName]
    deriving (Show,Eq,Ord)

instance Extension ExtSubjectAltName where
    extOID = const [2,5,29,17]
    extEncode (ExtSubjectAltName names) = encodeGeneralNames names
    extDecode l = runParseASN1 (ExtSubjectAltName <$> parseGeneralNames) l

-- | Provide a mean to identify the public key corresponding to the private key
-- used to signed a certificate.
data ExtAuthorityKeyId = ExtAuthorityKeyId B.ByteString
    deriving (Show,Eq)

instance Extension ExtAuthorityKeyId where
    extOID _ = [2,5,29,35]
    extEncode (ExtAuthorityKeyId keyid) =
        [Start Sequence,Other Context 0 keyid,End Sequence]
    extDecode [Start Sequence,Other Context 0 keyid,End Sequence] =
        Right $ ExtAuthorityKeyId keyid
    extDecode _ = Left "unknown sequence"

-- | Identify how CRL information is obtained
data ExtCrlDistributionPoints = ExtCrlDistributionPoints [DistributionPoint]
    deriving (Show,Eq)

-- | Reason flag for the CRL
data ReasonFlag =
      Reason_Unused
    | Reason_KeyCompromise
    | Reason_CACompromise
    | Reason_AffiliationChanged
    | Reason_Superseded
    | Reason_CessationOfOperation
    | Reason_CertificateHold
    | Reason_PrivilegeWithdrawn
    | Reason_AACompromise
    deriving (Show,Eq,Ord,Enum)

-- | Distribution point as either some GeneralNames or a DN
data DistributionPoint =
      DistributionPointFullName [AltName]
    | DistributionNameRelative DistinguishedName
    deriving (Show,Eq)

instance Extension ExtCrlDistributionPoints where
    extOID _ = [2,5,29,31]
    extEncode = error "extEncode ExtCrlDistributionPoints unimplemented"
    extDecode = error "extDecode ExtCrlDistributionPoints unimplemented"
    --extEncode (ExtCrlDistributionPoints )

parseGeneralNames :: ParseASN1 [AltName]
parseGeneralNames = do
    c <- getNextContainer Sequence
    r <- sequence $ map toStringy c
    return r
  where
        toStringy (Other Context 1 b) = return $ AltNameRFC822 $ BC.unpack b
        toStringy (Other Context 2 b) = return $ AltNameDNS $ BC.unpack b
        toStringy (Other Context 6 b) = return $ AltNameURI $ BC.unpack b
        toStringy (Other Context 7 b) = return $ AltNameIP  b
        toStringy b                   = throwError ("GeneralNames: not coping with anything else " ++ show b)

encodeGeneralNames :: [AltName] -> [ASN1]
encodeGeneralNames names =
    [Start Sequence]
    ++ map encodeAltName names
    ++ [End Sequence]
  where encodeAltName (AltNameRFC822 n) = Other Context 1 $ BC.pack n
        encodeAltName (AltNameDNS n)    = Other Context 2 $ BC.pack n
        encodeAltName (AltNameURI n)    = Other Context 6 $ BC.pack n
        encodeAltName (AltNameIP n)     = Other Context 7 $ n

bitsToFlags :: Enum a => BitArray -> [a]
bitsToFlags bits = concat $ flip map [0..(bitArrayLength bits-1)] $ \i -> do
        let isSet = bitArrayGetBit bits i
        if isSet then [toEnum $ fromIntegral i] else []

flagsToBits :: Enum a => [a] -> BitArray
flagsToBits flags = foldl bitArraySetBit bitArrayEmpty $ map (fromIntegral . fromEnum) flags
  where bitArrayEmpty = toBitArray (B.pack [0,0]) 7
