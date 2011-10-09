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
	( CertificateExt
	, Ext(..)
	, ExtKeyUsageFlag(..)
	, extDecode
	) where

import qualified Data.ByteString.Lazy as L
import Data.ASN1.DER
import Data.ASN1.BitArray
import Data.Certificate.X509.Internal

type CertificateExt = (OID, Bool, [ASN1])

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

-- RFC 5280
oidSubjectKeyId, oidKeyUsage, oidBasicConstraints, oidDistributionPoints,
                 oidPolicies, oidPoliciesMapping, oidAuthorityKeyId :: OID
oidSubjectKeyId       = [2,5,29,14]
oidKeyUsage           = [2,5,29,15]
oidBasicConstraints   = [2,5,29,19]
oidDistributionPoints = [2,5,29,31]
oidPolicies           = [2,5,29,32]
oidPoliciesMapping    = [2,5,29,33]
oidAuthorityKeyId     = [2,5,29,35]

data Ext =
	  ExtBasicConstraints Bool
	| ExtKeyUsage [ExtKeyUsageFlag]
	| ExtSubjectKeyId L.ByteString
	deriving (Show,Eq)

extDecode :: CertificateExt -> Maybe Ext
extDecode (oid, _, asn1)
	| oid == oidBasicConstraints = decodeBasicConstraints asn1
	| oid == oidSubjectKeyId     = decodeSubjectKeyId asn1
	| oid == oidKeyUsage         = decodeKeyUsage asn1
	| otherwise                  = Nothing
	where
		-- basic constraints
		decodeBasicConstraints [Start Sequence,Boolean b,End Sequence] =
			Just (ExtBasicConstraints b)
		decodeBasicConstraints _ = Nothing
		-- subject key id
		decodeSubjectKeyId [OctetString o] =
			Just (ExtSubjectKeyId o)
		decodeSubjectKeyId _ = Nothing
		-- key usage
		decodeKeyUsage [BitString bits] = Just $ ExtKeyUsage $ bitsToFlags bits
		decodeKeyUsage _ = Nothing

		bitsToFlags bits =
			let nb = bitArrayLength bits in
			concat $ flip map [0..(nb-1)] $ \i -> do
				let isSet = bitArrayGetBit bits i
				if isSet then [toEnum $ fromIntegral i] else []
