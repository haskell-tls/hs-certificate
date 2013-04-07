module System.Certificate.X509.MacOS
	( getSystemCertificateStore
	) where

import Data.PEM (pemParseLBS, PEM(..))
import Data.Certificate.X509
import System.Process
import qualified Data.ByteString.Lazy as LBS
import Control.Applicative
import Data.Either

import Data.CertificateStore

rootCAKeyChain :: String
rootCAKeyChain = "/System/Library/Keychains/SystemRootCertificates.keychain"

listInKeyChain :: String -> IO [X509]
listInKeyChain keyChain = do
    (_, Just hout, _, ph) <- createProcess (proc "security" ["find-certificate", "-pa", keyChain]) { std_out = CreatePipe }
    pems <- either error id . pemParseLBS <$> LBS.hGetContents hout
    let targets = rights $ map (decodeCertificate . LBS.fromChunks .  pure . pemContent) $ filter ((=="CERTIFICATE") . pemName) pems
    _ <- targets `seq` waitForProcess ph
    return targets

getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore = makeCertificateStore <$> listInKeyChain rootCAKeyChain
