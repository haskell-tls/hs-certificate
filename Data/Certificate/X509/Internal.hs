module Data.Certificate.X509.Internal
        ( module Data.ASN1.Parse
        , makeASN1Sequence
        , asn1Container
        , OID
        ) where

import Data.ASN1.Stream
import Data.ASN1.Parse

type OID = [Integer]

asn1Container :: ASN1ConstructionType -> [ASN1] -> [ASN1]
asn1Container ty l = [Start ty] ++ l ++ [End ty]

makeASN1Sequence :: [ASN1] -> [[ASN1]]
makeASN1Sequence list =
        let (l1, l2) = getConstructedEnd 0 list in
        case l2 of
                [] -> []
                _  -> l1 : makeASN1Sequence l2

