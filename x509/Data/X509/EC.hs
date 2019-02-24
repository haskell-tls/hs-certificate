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
      serializePoint
    , deserializePoint
    , ecPubKeyCurve
    , ecPubKeyCurveName
    , ecPrivKeyCurve
    , ecPrivKeyCurveName
    , lookupCurveNameByOID
    ) where

import           Data.ASN1.OID
import           Data.List               (find)

import           Data.X509.OID
import           Data.X509.PrivateKey
import           Data.X509.PublicKey

import           Crypto.Number.Serialize (i2ospOf, os2ip)
import qualified Crypto.PubKey.ECC.Prim  as ECC
import qualified Crypto.PubKey.ECC.Types as ECC

import qualified Data.ByteString         as B

-- | Serialize an EC point and make sure the serialized point fits into the bytestring space
-- allowed by the curve.
serializePoint :: ECC.Curve -> ECC.Point -> Either String SerializedPoint
serializePoint _curve ECC.PointO = Left "Serializing Point0 not supported"
serializePoint curve (ECC.Point px py) = SerializedPoint . B.cons ptFormat <$> output
    where
      ptFormat = 4 -- non compressed format
      output = (<>) <$> serializedX <*> serializedY
      serializedX = maybe
                    (Left "could not serialize the point's x dimension into a bytestring of given size")
                    Right
                    $ i2ospOf dimensionLength px
      serializedY = maybe
                    (Left "could not serialize the point's y dimension into a bytestring of given size")
                    Right
                    $ i2ospOf dimensionLength py

      bits            = ECC.curveSizeBits curve
      dimensionLength = (bits + 7) `div` 8

-- | Read an EC point from a serialized format and make sure the point is
-- valid for the specified curve.
deserializePoint :: ECC.Curve -> SerializedPoint -> Either String ECC.Point
deserializePoint curve (SerializedPoint bs) =
    case B.uncons bs of
        Nothing                -> Left "too few bytes in the serialized point, could not extract the format prefix"
        Just (ptFormat, input) ->
            case ptFormat of
                4 -> if B.length input /= 2 * dimensionLength
                        then Left $ "incorrect length of the serialized point part of the bytestring: expected " <>
                               show (2 * dimensionLength) <> " but got " <> show (B.length input)
                        else
                            let (x, y) = B.splitAt dimensionLength input
                                p      = ECC.Point (os2ip x) (os2ip y)
                             in if ECC.isPointValid curve p
                                    then Right p
                                    else Left "the point is invalid for the curve"
                -- 2 and 3 for compressed format.
                _ -> Left $ "expected prefix 4 for uncompressed format but got " <> show ptFormat
  where bits            = ECC.curveSizeBits curve
        dimensionLength = (bits + 7) `div` 8

-- | Return the curve associated to an EC Public Key.  This does not check
-- if a curve in explicit format is valid: if the input is not trusted one
-- should consider 'ecPubKeyCurveName' instead.
ecPubKeyCurve :: PubKeyEC -> Either String ECC.Curve
ecPubKeyCurve (PubKeyEC_Named name _) = Right $ ECC.getCurveByName name
ecPubKeyCurve pub@PubKeyEC_Prime{}    =
    fmap buildCurve $
        deserializePoint (buildCurve undefined) (pubkeyEC_generator pub)
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
ecPrivKeyCurve :: PrivKeyEC -> Either String ECC.Curve
ecPrivKeyCurve (PrivKeyEC_Named name _) = Right $ ECC.getCurveByName name
ecPrivKeyCurve priv@PrivKeyEC_Prime{}   =
    fmap buildCurve $
        deserializePoint (buildCurve undefined) (privkeyEC_generator priv)
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
