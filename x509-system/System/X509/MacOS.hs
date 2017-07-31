module System.X509.MacOS
    ( getSystemCertificateStore
    ) where

import Data.PEM (pemParseLBS, PEM(..))
import System.Process
import qualified Data.ByteString.Lazy as LBS
import Control.Applicative
import Data.Either

import Data.X509
import Data.X509.CertificateStore

rootCAKeyChain :: FilePath
rootCAKeyChain = "/System/Library/Keychains/SystemRootCertificates.keychain"

systemKeyChain :: FilePath
systemKeyChain = "/Library/Keychains/System.keychain"

listInKeyChains :: [FilePath] -> IO [SignedCertificate]
listInKeyChains keyChains = do
    (_, Just hout, _, ph) <- createProcess (proc "security" ("find-certificate" : "-pa" : keyChains)) { std_out = CreatePipe }
    pems <- either error id . pemParseLBS <$> LBS.hGetContents hout
    let targets = rights $ map (decodeSignedCertificate . pemContent) $ filter ((=="CERTIFICATE") . pemName) pems
    _ <- targets `seq` waitForProcess ph
    return targets

getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore = makeCertificateStore <$> listInKeyChains [rootCAKeyChain, systemKeyChain]
