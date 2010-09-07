import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import Data.Certificate.X509
import Data.Certificate.Key
import Data.Certificate.PEM
import System
import Text.Hexdump
import Control.Monad
import Data.Maybe

import Data.ASN1.DER

readcert :: FilePath -> IO (Either String Certificate)
readcert file = B.readFile file >>= return . either Left (decodeCertificate . L.fromChunks . (:[])) . parsePEMCert

readprivate :: FilePath -> IO (Either String PrivateKey)
readprivate file = B.readFile file >>= return . either Left (decodePrivateKey . L.fromChunks . (:[])) . parsePEMKey

showCert :: Certificate -> String
showCert cert =
	let ver = certVersion cert in
	let ser = certSerial cert in
	let sigalg = certSignatureAlg cert in
	let idn = certIssuerDN cert in
	let sdn = certSubjectDN cert in
	let valid = certValidity cert in
	let pk = certPubKey cert in
	let exts = certExtensions cert in
	let sig = certSignature cert in
	let other = certOthers cert in

	unlines [
		"version: " ++ show ver,
		"serial:  " ++ show ser,
		"sigalg:  " ++ show sigalg,
		"issuer:  " ++ show idn,
		"subject: " ++ show sdn,
		"valid:   " ++ show valid,
		"pk:      " ++ show pk,
		"exts:    " ++ show exts,
		"sig:     " ++ show sig,
		"other:   " ++ show other ]

showKey :: PrivateKey -> String
showKey key =
	unlines [
		"version:          " ++ (show $ privKey_version key),
		"len-modulus:      " ++ (show $ privKey_lenmodulus key),
		"modulus:          " ++ (show $ privKey_modulus key),
		"public exponant:  " ++ (show $ privKey_public_exponant key),
		"private exponant: " ++ (show $ privKey_private_exponant key),
		"coefficient:      " ++ (show $ privKey_coef key)
		]

main = do
	args <- getArgs
	case args !! 0 of
		"private" -> do
			c <- readprivate (args !! 1)
			case c of
				Left err   -> error err
				Right cert -> putStrLn $ showKey cert
		"cert" -> do
			c <- readcert (args !! 1)
			case c of
				Left err   -> error err
				Right cert -> putStrLn $ showCert cert
