module Tests.Unit
	( runTests
	) where

import System.Directory
import Test.HUnit
import Control.Monad
import Control.Applicative ((<$>))
import Control.Exception
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
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
	forM certs $ \(name, cert) -> do
		case decodeCertificate $ L.fromChunks [cert] of
			Left err -> putStrLn ("cannot decode certificate " ++ name ++ " " ++ show err)
			Right c  -> do
				case certSignatureAlg c of
					SignatureALG_Unknown oid -> putStrLn ("unknown signature algorithm " ++ show oid ++ " decoding " ++ name)
					_                        -> return ()
				case certPubKey c of
					(PubKey (PubKeyALG_Unknown oid) _) -> putStrLn ("unknown public key alg " ++ show (certPubKey c) ++ " decoding " ++ name)
					(PubKey _ (PubKeyUnknown l))       -> putStrLn ("unknown public key " ++ show (certPubKey c) ++ " decoding " ++ name)
					(PubKey _ (PubKeyECDSA x))         -> putStrLn ("unknown public ECDSA key " ++ show x ++ " decoding " ++ name)
					_                                  -> return ()
				return ()
	return ()
