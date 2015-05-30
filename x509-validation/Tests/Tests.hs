{-# LANGUAGE OverloadedStrings #-}
module Main where

import Test.Tasty
import Test.Tasty.HUnit

import qualified Data.ByteString as B

import Data.ASN1.Types
import Data.X509
import Data.X509.Validation


cert :: B.ByteString -> Certificate
cert subject = Certificate 1 1
    (SignatureALG HashSHA512 PubKeyALG_ECDSA)
    dn
    undefined
    dn
    (PubKeyUnknown [0] "")
    (Extensions Nothing)

  where
    dn = DistinguishedName [((getObjectID DnCommonName), ASN1CharacterString UTF8 subject)]


main = defaultMain $ testGroup "X509"
    [ testGroup "validateCertificateName"
        [ testCase "should accept certificate with an exact matching domain" $
            validateCertificateName "example.com" (cert "example.com") @?= []

        , testCase "should reject a certificate for a public suffix (TLD)" $
            validateCertificateName "com" (cert "com") @?= [NameMismatch "com"]

        , testCase "should reject a certificate for a public suffix (SLD)" $
            validateCertificateName "co.uk" (cert "co.uk") @?= [NameMismatch "co.uk"]

        , testCase "should reject a wildcard certificate for a public suffix (TLD)" $
            validateCertificateName "example.com" (cert "*.com") @?= [NameMismatch "example.com"]

        , testCase "should reject a wildcard certificate for a public suffix (SLD)" $
            validateCertificateName "example.co.uk" (cert "*.co.uk") @?= [NameMismatch "example.co.uk"]

        , testCase "should accept wildcard certificate with an exact matching domain" $
            validateCertificateName "test.git.io" (cert "*.git.io") @?= []

        , testCase "should reject wildcard certificate with an mismatching subdomain (RFC6125 section 6.4.3 rule 2)" $
            validateCertificateName "sub.test.example.com" (cert "*.example.com") @?= [NameMismatch "sub.test.example.com"]
        ]
    ]
