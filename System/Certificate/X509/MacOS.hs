module System.Certificate.X509.MacOS
	( findCertificate
	) where

import Data.Certificate.X509
import Data.Certificate.PEM
import System.Process
import Data.ByteString hiding (filter, map)
import qualified Data.ByteString.Lazy as LBS
import Control.Applicative
import Data.Either
import Data.Maybe

findCertificate :: (X509 -> Bool) -> IO (Maybe X509)
findCertificate f = do
  (_, h, _, ph) <- runInteractiveCommand "security find-certificate -pa"
  waitForProcess ph
  pems <- parsePEMs <$> hGetContents h
  let targets = rights $ map (decodeCertificate . LBS.fromChunks .  pure . snd) $ filter ((=="CERTIFICATE") . fst) pems
  return $ listToMaybe $ filter f targets
