-- |
-- Module      : Data.X509.EC
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Utilities related to Elliptic Curve certificates and keys.
--
module Data.X509.EC
    (
      unserializePoint
    , ecPubKeyCurve
    , ecPubKeyCurveName
    , ecPrivKeyCurve
    , ecPrivKeyCurveName
    , lookupCurveNameByOID
    ) where

import Data.ASN1.OID
import Data.List (find)

import Data.X509.OID
import Data.X509.PublicKey
import Data.X509.PrivateKey

import qualified Crypto.PubKey.ECC.Prim  as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import           Crypto.Number.Serialize (os2ip)

import qualified Data.ByteString as B

-- | Read an EC point from a serialized format and make sure the point is
-- valid for the specified curve.
unserializePoint :: ECC.Curve -> SerializedPoint -> Maybe ECC.Point
unserializePoint curve (SerializedPoint bs) =
    case B.uncons bs of
        Nothing                -> Nothing
        Just (ptFormat, input) ->
            case ptFormat of
                4 -> if B.length input /= 2 * bytes
                        then Nothing
                        else
                            let (x, y) = B.splitAt bytes input
                                p      = ECC.Point (os2ip x) (os2ip y)
                             in if ECC.isPointValid curve p
                                    then Just p
                                    else Nothing
                -- 2 and 3 for compressed format.
                _ -> Nothing
  where bits  = ECC.curveSizeBits curve
        bytes = (bits + 7) `div` 8

-- | Return the curve associated to an EC Public Key.  This does not check
-- if a curve in explicit format is valid: if the input is not trusted one
-- should consider 'ecPubKeyCurveName' instead.
ecPubKeyCurve :: PubKeyEC -> Maybe ECC.Curve
ecPubKeyCurve (PubKeyEC_Named name _) = Just $ ECC.getCurveByName name
ecPubKeyCurve pub@PubKeyEC_Prime{}    =
    fmap buildCurve $
        unserializePoint (buildCurve undefined) (pubkeyEC_generator pub)
  where
    prime = pubkeyEC_prime pub
    buildCurve g =
        let cc = ECC.CurveCommon
                     { ECC.ecc_a = pubkeyEC_a        pub
                     , ECC.ecc_b = pubkeyEC_b        pub
                     , ECC.ecc_g = g
                     , ECC.ecc_n = pubkeyEC_order    pub
                     , ECC.ecc_h = pubkeyEC_cofactor pub
                     }
         in ECC.CurveFP (ECC.CurvePrime prime cc)

-- | Return the name of a standard curve associated to an EC Public Key
ecPubKeyCurveName :: PubKeyEC -> Maybe ECC.CurveName
ecPubKeyCurveName (PubKeyEC_Named name _) = Just name
ecPubKeyCurveName pub@PubKeyEC_Prime{}    =
    find matchPrimeCurve $ enumFrom $ toEnum 0
  where
    matchPrimeCurve c =
        case ECC.getCurveByName c of
            ECC.CurveFP (ECC.CurvePrime p cc) ->
                ECC.ecc_a cc == pubkeyEC_a pub     &&
                ECC.ecc_b cc == pubkeyEC_b pub     &&
                ECC.ecc_n cc == pubkeyEC_order pub &&
                p            == pubkeyEC_prime pub
            _                                 -> False

-- | Return the EC curve associated to an EC Private Key.  This does not check
-- if a curve in explicit format is valid: if the input is not trusted one
-- should consider 'ecPrivKeyCurveName' instead.
ecPrivKeyCurve :: PrivKeyEC -> Maybe ECC.Curve
ecPrivKeyCurve (PrivKeyEC_Named name _) = Just $ ECC.getCurveByName name
ecPrivKeyCurve priv@PrivKeyEC_Prime{}   =
    fmap buildCurve $
        unserializePoint (buildCurve undefined) (privkeyEC_generator priv)
  where
    prime = privkeyEC_prime priv
    buildCurve g =
        let cc = ECC.CurveCommon
                     { ECC.ecc_a = privkeyEC_a        priv
                     , ECC.ecc_b = privkeyEC_b        priv
                     , ECC.ecc_g = g
                     , ECC.ecc_n = privkeyEC_order    priv
                     , ECC.ecc_h = privkeyEC_cofactor priv
                     }
         in ECC.CurveFP (ECC.CurvePrime prime cc)

-- | Return the name of a standard curve associated to an EC Private Key
ecPrivKeyCurveName :: PrivKeyEC -> Maybe ECC.CurveName
ecPrivKeyCurveName (PrivKeyEC_Named name _) = Just name
ecPrivKeyCurveName priv@PrivKeyEC_Prime{}   =
    find matchPrimeCurve $ enumFrom $ toEnum 0
  where
    matchPrimeCurve c =
        case ECC.getCurveByName c of
            ECC.CurveFP (ECC.CurvePrime p cc) ->
                ECC.ecc_a cc == privkeyEC_a priv     &&
                ECC.ecc_b cc == privkeyEC_b priv     &&
                ECC.ecc_n cc == privkeyEC_order priv &&
                p            == privkeyEC_prime priv
            _                                 -> False

-- | Return the curve name associated to an OID
lookupCurveNameByOID :: OID -> Maybe ECC.CurveName
lookupCurveNameByOID = lookupByOID curvesOIDTable
