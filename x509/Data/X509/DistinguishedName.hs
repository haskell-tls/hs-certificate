-- |
-- Module      : Data.X509.DistinguishedName
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Distinguished names types and functions

{-# LANGUAGE CPP #-}
module Data.X509.DistinguishedName
    ( DistinguishedName(..)
    , DistinguishedNameInner(..)
    , ASN1CharacterString(..)
    -- Distinguished Name Elements
    , DnElement(..)
    , getDnElement
    ) where

import Control.Applicative
#if MIN_VERSION_base(4,9,0)
import           Data.Semigroup
#else
import           Data.Monoid
#endif
import Data.ASN1.Types
import Data.X509.Internal

-- | A list of OID and strings.
newtype DistinguishedName = DistinguishedName { getDistinguishedElements :: [(OID, ASN1CharacterString)] }
    deriving (Show,Eq,Ord)

-- | Elements commonly available in a 'DistinguishedName' structure
data DnElement =
      DnCommonName       -- ^ CN
    | DnCountry          -- ^ Country
    | DnOrganization     -- ^ O
    | DnOrganizationUnit -- ^ OU
    | DnEmailAddress     -- ^ Email Address (legacy)
    deriving (Show,Eq)

instance OIDable DnElement where
    getObjectID DnCommonName       = [2,5,4,3]
    getObjectID DnCountry          = [2,5,4,6]
    getObjectID DnOrganization     = [2,5,4,10]
    getObjectID DnOrganizationUnit = [2,5,4,11]
    getObjectID DnEmailAddress     = [1,2,840,113549,1,9,1]

-- | Try to get a specific element in a 'DistinguishedName' structure
getDnElement :: DnElement -> DistinguishedName -> Maybe ASN1CharacterString
getDnElement element (DistinguishedName els) = lookup (getObjectID element) els

-- | Only use to encode a DistinguishedName without including it in a
-- Sequence
newtype DistinguishedNameInner = DistinguishedNameInner DistinguishedName
    deriving (Show,Eq)

#if MIN_VERSION_base(4,9,0)
instance Semigroup DistinguishedName where
    DistinguishedName l1 <> DistinguishedName l2 = DistinguishedName (l1++l2)
#endif

instance Monoid DistinguishedName where
    mempty  = DistinguishedName []
#if !(MIN_VERSION_base(4,11,0))
    mappend (DistinguishedName l1) (DistinguishedName l2) = DistinguishedName (l1++l2)
#endif

instance ASN1Object DistinguishedName where
    toASN1 dn = \xs -> encodeDN dn ++ xs
    fromASN1  = runParseASN1State parseDN

-- FIXME parseDNInner in fromASN1 is probably wrong as we don't have a container
-- and thus hasNext should be replaced by a isFinished clause.
instance ASN1Object DistinguishedNameInner where
    toASN1 (DistinguishedNameInner dn) = \xs -> encodeDNinner dn ++ xs
    fromASN1 = runParseASN1State (DistinguishedNameInner . DistinguishedName <$> parseDNInner)

parseDN :: ParseASN1 DistinguishedName
parseDN = DistinguishedName <$> onNextContainer Sequence parseDNInner

parseDNInner :: ParseASN1 [(OID, ASN1CharacterString)]
parseDNInner = concat `fmap` getMany parseOneDN

parseOneDN :: ParseASN1 [(OID, ASN1CharacterString)]
parseOneDN = onNextContainer Set $ getMany $ do
    s <- getNextContainer Sequence
    case s of
        [OID oid, ASN1String cs] -> return (oid, cs)
        _                        -> throwParseError ("expecting [OID,String] got " ++ show s)

encodeDNinner :: DistinguishedName -> [ASN1]
encodeDNinner (DistinguishedName dn) = concatMap dnSet dn
  where dnSet (oid, cs) = asn1Container Set $ asn1Container Sequence [OID oid, ASN1String cs]

encodeDN :: DistinguishedName -> [ASN1]
encodeDN dn = asn1Container Sequence $ encodeDNinner dn
