module Tests.Unit
	( runTests
	) where

import System.Directory
import Test.HUnit
import Control.Monad
import Control.Applicative ((<$>))
import Control.Exception
import qualified Data.ByteString as B
import Data.Certificate.X509
import Data.Certificate.PEM
import Data.List (isPrefixOf)

readAllSystemCertificates = do
	certfiles <- filter (not . isPrefixOf ".") <$> getDirectoryContents "/etc/ssl/certs"
	foldM getCertData [] certfiles 
	where getCertData acc certfile = do
		certdata <- try (B.readFile ("/etc/ssl/certs/" ++ certfile)) :: IO (Either IOException B.ByteString)
		case either (const Nothing) (parsePEMCert) $ certdata of
			Nothing -> return acc
			Just x  -> return ((certfile, x) : acc)

runTests :: IO ()
runTests = do
	certs <- readAllSystemCertificates
	return ()
