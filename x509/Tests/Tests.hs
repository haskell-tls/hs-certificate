{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Test.Framework (defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Test.QuickCheck

import qualified Data.ByteString as B

import Control.Applicative
import Control.Monad

import Data.ASN1.Types
import Data.X509
import qualified Crypto.Types.PubKey.RSA as RSA
import qualified Crypto.Types.PubKey.DSA as DSA

import Data.Time.Clock
import Data.Time.Clock.POSIX

instance Arbitrary RSA.PublicKey where
    arbitrary = do
        bytes <- elements [64,128,256]
        e     <- elements [0x3,0x10001]
        n     <- choose (2^(8*(bytes-1)),2^(8*bytes))
        return $ RSA.PublicKey { RSA.public_size = bytes
                               , RSA.public_n    = n
                               , RSA.public_e    = e
                               }

instance Arbitrary DSA.Params where
    arbitrary = DSA.Params <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary DSA.PublicKey where
    arbitrary = DSA.PublicKey <$> arbitrary <*> arbitrary

instance Arbitrary PubKey where
    arbitrary = oneof
        [ PubKeyRSA <$> arbitrary
        , PubKeyDSA <$> arbitrary
        --, PubKeyECDSA ECDSA_Hash_SHA384 <$> (B.pack <$> replicateM 384 arbitrary)
        ]

instance Arbitrary HashALG where
    arbitrary = elements [HashMD2,HashMD5,HashSHA1,HashSHA224,HashSHA256,HashSHA384,HashSHA512]

instance Arbitrary PubKeyALG where
    arbitrary = elements [PubKeyALG_RSA,PubKeyALG_DSA,PubKeyALG_ECDSA,PubKeyALG_DH]

instance Arbitrary SignatureALG where
    -- unfortunately as the encoding of this is a single OID as opposed to two OID,
    -- the testing need to limit itself to Signature ALG that has been defined in the OID database. 
    -- arbitrary = SignatureALG <$> arbitrary <*> arbitrary
    arbitrary = elements
        [ SignatureALG HashSHA1 PubKeyALG_RSA
        , SignatureALG HashMD5 PubKeyALG_RSA
        , SignatureALG HashMD2 PubKeyALG_RSA
        , SignatureALG HashSHA256 PubKeyALG_RSA
        , SignatureALG HashSHA384 PubKeyALG_RSA
        , SignatureALG HashSHA1 PubKeyALG_DSA
        , SignatureALG HashSHA224 PubKeyALG_ECDSA
        , SignatureALG HashSHA256 PubKeyALG_ECDSA
        , SignatureALG HashSHA384 PubKeyALG_ECDSA
        , SignatureALG HashSHA512 PubKeyALG_ECDSA
        ]

arbitraryBS r1 r2 = choose (r1,r2) >>= \l -> (B.pack <$> replicateM l arbitrary)

instance Arbitrary ASN1StringEncoding where
    arbitrary = elements [IA5,UTF8]
instance Arbitrary DistinguishedName where
    arbitrary = DistinguishedName <$> (choose (1,5) >>= \l -> replicateM l arbitraryDE)
      where arbitraryDE = (,) <$> arbitrary <*> ((,) <$> arbitrary <*> arbitraryBS 2 36)
instance Arbitrary UTCTime where
    arbitrary = posixSecondsToUTCTime . fromIntegral <$> (arbitrary :: Gen Int)
instance Arbitrary Certificate where
    arbitrary = Certificate <$> pure 2
                            <*> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> pure (Extensions Nothing)

assertEq a b
    | a == b    = True
    | otherwise = error (show b ++ " got: " ++ show a)

property_unmarshall_marshall_id :: (Show o, Arbitrary o, ASN1Object o, Eq o) => o -> Bool
property_unmarshall_marshall_id o = (fromASN1 (toASN1 o []) `assertEq` Right (o, []))

main = defaultMain
    [ testGroup "asn1 objects unmarshall.marshall=id"
        [ testProperty "pubkey" (property_unmarshall_marshall_id :: PubKey -> Bool)
        , testProperty "signature alg" (property_unmarshall_marshall_id :: SignatureALG -> Bool)
        , testProperty "certificate" (property_unmarshall_marshall_id :: Certificate -> Bool)
        ]
    ]
