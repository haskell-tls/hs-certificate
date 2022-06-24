{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module System.X509.MacOS
    ( getSystemCertificateStore
    ) where

import qualified Data.ByteString.Lazy as LBS
import Data.Either
import Data.PEM (PEM (..), pemParseLBS)
import System.Exit
import System.Process

import Data.X509
import Data.X509.CertificateStore

rootCAKeyChain :: FilePath
rootCAKeyChain = "/System/Library/Keychains/SystemRootCertificates.keychain"

systemKeyChain :: FilePath
systemKeyChain = "/Library/Keychains/System.keychain"

listInKeyChains :: [FilePath] -> IO [SignedCertificate]
listInKeyChains keyChains = do
    withCreateProcess
        (proc "security" ("find-certificate" : "-pa" : keyChains))
          { std_out = CreatePipe
          , create_group = True  -- SIGINT sent to us should not also kill the spawned process
          } $
      \_ (Just hout) _ ph -> do
        !(ePems :: Either String [PEM]) <- pemParseLBS <$> LBS.hGetContents hout
        let eTargets = rights . map (decodeSignedCertificate . pemContent) . filter ((=="CERTIFICATE") . pemName)
                    <$> ePems
        waitForProcess ph >>= \case
            ExitFailure code ->
                error $ "failed to fetch certificates, process died with " <> show code <> " code"
            _ ->
                pure ()
        either error pure eTargets

getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore = makeCertificateStore <$> listInKeyChains [rootCAKeyChain, systemKeyChain]
