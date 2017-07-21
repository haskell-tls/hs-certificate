-- |
-- Module      : Data.X509.Ext
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- extension processing module.
--
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
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
    , ExtNetscapeComment(..)
    , AltName(..)
    , DistributionPoint(..)
    , ReasonFlag(..)
    -- * Accessor turning extension into a specific one
    , extensionGet
    , extensionGetE
    , extensionDecode
    , extensionEncode
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.ASN1.Types
import Data.ASN1.Parse
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
import Data.Proxy
import Data.List (find)
import Data.X509.ExtensionRaw
import Data.X509.DistinguishedName
import Control.Applicative
import Control.Monad

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
--
-- Errata: turns out, the content is not necessarily ASN1,
-- it could be data that is only parsable by the extension
-- e.g. raw ascii string. Add method to parse and encode with
-- ByteString
class Extension a where
    extOID           :: a -> OID
    extHasNestedASN1 :: Proxy a -> Bool
    extEncode        :: a -> [ASN1]
    extDecode        :: [ASN1] -> Either String a

    extDecodeBs :: B.ByteString -> Either String a
    extDecodeBs = (either (Left . show) Right . decodeASN1' BER) >=> extDecode

    extEncodeBs :: a -> B.ByteString
    extEncodeBs = encodeASN1' DER . extEncode


-- | Get a specific extension from a lists of raw extensions
extensionGet :: Extension a => Extensions -> Maybe a
extensionGet (Extensions Nothing)  = Nothing
extensionGet (Extensions (Just l)) = findExt l
  where findExt []     = Nothing
        findExt (x:xs) = case extensionDecode x of
                            Just (Right e) -> Just e
                            _              -> findExt xs

-- | Get a specific extension from a lists of raw extensions
extensionGetE :: Extension a => Extensions -> Maybe (Either String a)
extensionGetE (Extensions Nothing)  = Nothing
extensionGetE (Extensions (Just l)) = findExt l
  where findExt []     = Nothing
        findExt (x:xs) = case extensionDecode x of
                            Just r         -> Just r
                            _              -> findExt xs

-- | Try to decode an ExtensionRaw.
--
-- If this function return:
-- * Nothing, the OID doesn't match
-- * Just Left, the OID matched, but the extension couldn't be decoded
-- * Just Right, the OID matched, and the extension has been succesfully decoded
extensionDecode :: forall a . Extension a => ExtensionRaw -> Maybe (Either String a)
extensionDecode er@(ExtensionRaw oid _ content)
    | extOID (undefined :: a) /= oid      = Nothing
    | extHasNestedASN1 (Proxy :: Proxy a) = Just (tryExtRawASN1 er >>= extDecode)
    | otherwise                           = Just (extDecodeBs content)

-- | Encode an Extension to extensionRaw
extensionEncode :: forall a . Extension a => Bool -> a -> ExtensionRaw
extensionEncode critical ext
    | extHasNestedASN1 (Proxy :: Proxy a) = ExtensionRaw (extOID ext) critical (encodeASN1' DER $ extEncode ext)
    | otherwise                           = ExtensionRaw (extOID ext) critical (extEncodeBs ext)

-- | Basic Constraints
data ExtBasicConstraints = ExtBasicConstraints Bool (Maybe Integer)
    deriving (Show,Eq)

instance Extension ExtBasicConstraints where
    extOID = const [2,5,29,19]
    extHasNestedASN1 = const True
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
    extHasNestedASN1 = const True
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
    extHasNestedASN1 = const True
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
    extHasNestedASN1 = const True
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
    | AltNameXMPP String
    | AltNameDNSSRV String
    deriving (Show,Eq,Ord)

-- | Provide a way to supply alternate name that can be
-- used for matching host name.
data ExtSubjectAltName = ExtSubjectAltName [AltName]
    deriving (Show,Eq,Ord)

instance Extension ExtSubjectAltName where
    extOID = const [2,5,29,17]
    extHasNestedASN1 = const True
    extEncode (ExtSubjectAltName names) = encodeGeneralNames names
    extDecode l = runParseASN1 (ExtSubjectAltName <$> parseGeneralNames) l

-- | Provide a mean to identify the public key corresponding to the private key
-- used to signed a certificate.
data ExtAuthorityKeyId = ExtAuthorityKeyId B.ByteString
    deriving (Show,Eq)

instance Extension ExtAuthorityKeyId where
    extOID _ = [2,5,29,35]
    extHasNestedASN1 = const True
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
    extHasNestedASN1 = const True
    extEncode = error "extEncode ExtCrlDistributionPoints unimplemented"
    extDecode = error "extDecode ExtCrlDistributionPoints unimplemented"
    --extEncode (ExtCrlDistributionPoints )

parseGeneralNames :: ParseASN1 [AltName]
parseGeneralNames = onNextContainer Sequence $ getMany getAddr
  where
        getAddr = do
            m <- onNextContainerMaybe (Container Context 0) getComposedAddr
            case m of
                Nothing -> getSimpleAddr
                Just r  -> return r
        getComposedAddr = do
            n <- getNext
            case n of
                OID [1,3,6,1,5,5,7,8,5] -> do -- xmpp addr
                    c <- getNextContainerMaybe (Container Context 0)
                    case c of
                        Just [ASN1String cs] ->
                            case asn1CharacterToString cs of
                                Nothing -> throwParseError ("GeneralNames: invalid string for XMPP Addr")
                                Just s  -> return $ AltNameXMPP s
                        _ -> throwParseError ("GeneralNames: expecting string for XMPP Addr got: " ++ show c)
                OID [1,3,6,1,5,5,7,8,7] -> do -- DNSSRV addr
                    c <- getNextContainerMaybe (Container Context 0)
                    case c of
                        Just [ASN1String cs] ->
                            case asn1CharacterToString cs of
                                Nothing -> throwParseError ("GeneralNames: invalid string for DNSSrv Addr")
                                Just s  -> return $ AltNameDNSSRV s
                        _ -> throwParseError ("GeneralNames: expecting string for DNSSRV Addr got: " ++ show c)
                OID unknown -> throwParseError ("GeneralNames: unknown OID " ++ show unknown)
                _           -> throwParseError ("GeneralNames: expecting OID but got " ++ show n)

        getSimpleAddr = do
            n <- getNext
            case n of
                (Other Context 1 b) -> return $ AltNameRFC822 $ BC.unpack b
                (Other Context 2 b) -> return $ AltNameDNS $ BC.unpack b
                (Other Context 6 b) -> return $ AltNameURI $ BC.unpack b
                (Other Context 7 b) -> return $ AltNameIP  b
                _                   -> throwParseError ("GeneralNames: not coping with unknown stream " ++ show n)

encodeGeneralNames :: [AltName] -> [ASN1]
encodeGeneralNames names =
    [Start Sequence]
    ++ concatMap encodeAltName names
    ++ [End Sequence]
  where encodeAltName (AltNameRFC822 n) = [Other Context 1 $ BC.pack n]
        encodeAltName (AltNameDNS n)    = [Other Context 2 $ BC.pack n]
        encodeAltName (AltNameURI n)    = [Other Context 6 $ BC.pack n]
        encodeAltName (AltNameIP n)     = [Other Context 7 $ n]
        encodeAltName (AltNameXMPP n)   = [Start (Container Context 0),OID[1,3,6,1,5,5,7,8,5]
                                          ,Start (Container Context 0), ASN1String $ asn1CharacterString UTF8 n, End (Container Context 0)
                                          ,End (Container Context 0)]
        encodeAltName (AltNameDNSSRV n) = [Start (Container Context 0),OID[1,3,6,1,5,5,7,8,5]
                                          ,Start (Container Context 0), ASN1String $ asn1CharacterString UTF8 n, End (Container Context 0)
                                          ,End (Container Context 0)]

bitsToFlags :: Enum a => BitArray -> [a]
bitsToFlags bits = concat $ flip map [0..(bitArrayLength bits-1)] $ \i -> do
        let isSet = bitArrayGetBit bits i
        if isSet then [toEnum $ fromIntegral i] else []

flagsToBits :: Enum a => [a] -> BitArray
flagsToBits flags = foldl bitArraySetBit bitArrayEmpty $ map (fromIntegral . fromEnum) flags
  where bitArrayEmpty = toBitArray (B.pack [0,0]) 7

data ExtNetscapeComment = ExtNetscapeComment B.ByteString
    deriving (Show,Eq)

instance Extension ExtNetscapeComment where
    extOID _ = [2,16,840,1,113730,1,13]
    extHasNestedASN1 = const False
    extEncode = error "Extension: Netscape Comment do not contain nested ASN1"
    extDecode = error "Extension: Netscape Comment do not contain nested ASN1"
    extEncodeBs (ExtNetscapeComment b) = b
    extDecodeBs = Right . ExtNetscapeComment
