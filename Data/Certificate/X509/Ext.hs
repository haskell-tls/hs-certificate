-- |
-- Module      : Data.Certificate.X509.Ext
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- extension processing module.
--
module Data.Certificate.X509.Ext
        ( ExtensionRaw
        , Extension(..)
        -- * Common extension usually found in x509v3
        , ExtBasicConstraints(..)
        , ExtKeyUsage(..)
        , ExtKeyUsageFlag(..)
        , ExtSubjectKeyId(..)
        , ExtSubjectAltName(..)
        , ExtAuthorityKeyId(..)
        -- * Accessor turning extension into a specific one
        , extensionGet
        ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as L
import Data.ASN1.DER
import Data.ASN1.BitArray
import Data.Certificate.X509.Internal

type ExtensionRaw = (OID, Bool, [ASN1])

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
oidDistributionPoints = [2,5,29,31]
oidPolicies           = [2,5,29,32]
oidPoliciesMapping    = [2,5,29,33]
-}

class Extension a where
        extOID    :: a -> OID
        extEncode :: a -> [ASN1]
        extDecode :: [ASN1] -> Either String a

extensionGet :: Extension a => [ExtensionRaw] -> Maybe a
extensionGet []                = Nothing
extensionGet ((oid,_,asn1):xs) = case extDecode asn1 of
        Right b
                | oid == extOID b -> Just b
                | otherwise       -> extensionGet xs
        Left _                    -> extensionGet xs

data ExtBasicConstraints = ExtBasicConstraints Bool
        deriving (Show,Eq)

instance Extension ExtBasicConstraints where
        extOID = const [2,5,29,19]
        extEncode (ExtBasicConstraints b) = [Start Sequence,Boolean b,End Sequence]
        extDecode [Start Sequence,Boolean b,End Sequence] = Right (ExtBasicConstraints b)
        extDecode [Start Sequence,End Sequence] = Right (ExtBasicConstraints False)
        extDecode _ = Left "unknown sequence"

data ExtKeyUsage = ExtKeyUsage [ExtKeyUsageFlag]
        deriving (Show,Eq)

instance Extension ExtKeyUsage where
        extOID = const [2,5,29,15]
        extEncode (ExtKeyUsage flags) = [BitString $ flagsToBits flags]
        extDecode [BitString bits] = Right $ ExtKeyUsage $ bitsToFlags bits
        extDecode _ = Left "unknown sequence"

data ExtSubjectKeyId = ExtSubjectKeyId L.ByteString
        deriving (Show,Eq)

instance Extension ExtSubjectKeyId where
        extOID = const [2,5,29,14]
        extEncode (ExtSubjectKeyId o) = [OctetString o]
        extDecode [OctetString o] = Right $ ExtSubjectKeyId o
        extDecode _ = Left "unknown sequence"

data ExtSubjectAltName = ExtSubjectAltName [String]
        deriving (Show,Eq)

instance Extension ExtSubjectAltName where
        extOID = const [2,5,29,17]
        extEncode (ExtSubjectAltName names) =
                [Start Sequence]
                ++ map (Other Context 2 . BC.pack) names
                ++ [End Sequence]
        extDecode l = runParseASN1 parse l where
                parse = do
                        c <- getNextContainer Sequence
                        return $ ExtSubjectAltName $ map toStringy c
                toStringy (Other Context 2 b) = BC.unpack b
                toStringy b                   = error ("not coping with anything else " ++ show b)

data ExtAuthorityKeyId = ExtAuthorityKeyId B.ByteString
        deriving (Show,Eq)

instance Extension ExtAuthorityKeyId where
        extOID _ = [2,5,29,35]
        extEncode (ExtAuthorityKeyId keyid) =
                [Start Sequence,Other Context 0 keyid,End Sequence]
        extDecode [Start Sequence,Other Context 0 keyid,End Sequence] =
                Right $ ExtAuthorityKeyId keyid
        extDecode _ = Left "unknown sequence"

bitsToFlags :: Enum a => BitArray -> [a]
bitsToFlags bits = concat $ flip map [0..(bitArrayLength bits-1)] $ \i -> do
        let isSet = bitArrayGetBit bits i
        if isSet then [toEnum $ fromIntegral i] else []

flagsToBits :: Enum a => [a] -> BitArray
flagsToBits flags = foldl bitArraySetBit bitArrayEmpty $ map (fromIntegral . fromEnum) flags
        where bitArrayEmpty = BitArray 2 (L.pack [0,0])
