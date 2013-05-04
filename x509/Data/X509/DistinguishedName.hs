-- |
-- Module      : Data.X509.DistinguishedName
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Distinguished names types and functions
module Data.X509.DistinguishedName
    ( DistinguishedName(..)
    , DistinguishedNameInner(..)
    , ASN1Stringable

    -- Distinguished Name Elements
    , DnElement(..)
    , getDnElement
    ) where

import Control.Applicative
import Data.Monoid
import Data.ASN1.Types
import Data.X509.Internal
import Control.Monad.Error
import Data.ByteString (ByteString)

type ASN1Stringable = (ASN1StringEncoding, ByteString)

-- | A list of OID and strings.
newtype DistinguishedName = DistinguishedName { getDistinguishedElements :: [(OID, ASN1Stringable)] }
    deriving (Show,Eq,Ord)

-- | Elements commonly available in a 'DistinguishedName' structure
data DnElement =
      DnCommonName       -- ^ CN
    | DnCountry          -- ^ Country
    | DnOrganization     -- ^ O
    | DnOrganizationUnit -- ^ OU
    deriving (Show,Eq)

instance OIDable DnElement where
    getObjectID DnCommonName       = [2,5,4,3]
    getObjectID DnCountry          = [2,5,4,6]
    getObjectID DnOrganization     = [2,5,4,10]
    getObjectID DnOrganizationUnit = [2,5,4,11]

-- | Try to get a specific element in a 'DistinguishedName' structure
getDnElement :: DnElement -> DistinguishedName -> Maybe ASN1Stringable
getDnElement element (DistinguishedName els) = lookup (getObjectID element) els

-- | Only use to encode a DistinguishedName without including it in a
-- Sequence
newtype DistinguishedNameInner = DistinguishedNameInner DistinguishedName
    deriving (Show,Eq)

instance Monoid DistinguishedName where
    mempty  = DistinguishedName []
    mappend (DistinguishedName l1) (DistinguishedName l2) = DistinguishedName (l1++l2)

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

parseDNInner :: ParseASN1 [(OID, ASN1Stringable)]
parseDNInner = do
    n <- hasNext
    if n
        then liftM2 (:) parseOneDN parseDNInner
        else return []

parseOneDN :: ParseASN1 (OID, ASN1Stringable)
parseOneDN = onNextContainer Set $ do
    s <- getNextContainer Sequence
    case s of
        [OID oid, ASN1String encoding val] -> return (oid, (encoding, val))
        _                                  -> throwError "expecting sequence"

encodeDNinner :: DistinguishedName -> [ASN1]
encodeDNinner (DistinguishedName dn) = concatMap dnSet dn
  where dnSet (oid, str) = asn1Container Set $ asn1Container Sequence [OID oid, uncurry ASN1String str]

encodeDN :: DistinguishedName -> [ASN1]
encodeDN dn = asn1Container Sequence $ encodeDNinner dn
