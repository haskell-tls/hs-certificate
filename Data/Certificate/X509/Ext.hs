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
	) where

import Data.ASN1.DER
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
	deriving (Show,Eq)

-- RFC 5280
oidSubjectKeyId       = [2,5,29,14]
oidKeyUsage           = [2,5,29,15]
oidBasicConstraints   = [2,5,29,19]
oidDistributionPoints = [2,5,29,31]
oidPolicies           = [2,5,29,32]
oidPoliciesMapping    = [2,5,29,33]
oidAuthorityKeyId     = [2,5,29,35]
