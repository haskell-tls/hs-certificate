module System.Certificate.X509.MacOS
	( findCertificate
	) where

import Data.PEM (pemParseLBS, PEM(..))
import Data.Certificate.X509
import System.Process
import Data.ByteString hiding (filter, map)
import qualified Data.ByteString.Lazy as LBS
import Control.Applicative
import Data.Either
import Data.Maybe

keyChain :: String
keyChain = "/System/Library/Keychains/SystemRootCertificates.keychain"

findCertificate :: (X509 -> Bool) -> IO (Maybe X509)
findCertificate f = do
  (_, Just hout, _, ph) <- createProcess (proc "security" ["find-certificate", "-pa", keyChain]) { std_out = CreatePipe }
  pems <- either error id . pemParseLBS <$> LBS.hGetContents hout
  _ <- waitForProcess ph
  let targets = rights $ map (decodeCertificate . LBS.fromChunks .  pure . pemContent) $ filter ((=="CERTIFICATE") . pemName) pems
  return $ listToMaybe $ filter f targets
