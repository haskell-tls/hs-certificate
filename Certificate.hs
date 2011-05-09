{-# LANGUAGE DeriveDataTypeable, OverloadedStrings #-}

import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString as B
import qualified Data.Text.Lazy as T
import Data.Text.Lazy.Encoding (decodeUtf8)
import qualified Data.Certificate.X509 as X509
import Data.Certificate.KeyRSA as KeyRSA
import Data.Certificate.KeyDSA as KeyDSA
import Data.Certificate.PEM
import System.Console.CmdArgs
import Control.Monad
import Control.Applicative ((<$>))
import Data.Maybe
import System.Exit
import System.Certificate.X509 as SysCert

-- for signing/verifying certificate
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.MD2 as MD2
import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Cipher.RSA as RSA
import qualified Crypto.Cipher.DSA as DSA

import Data.ASN1.DER (decodeASN1Stream, ASN1(..), ASN1ConstructionType(..))
import Numeric

hexdump :: L.ByteString -> String
hexdump bs = concatMap hex $ L.unpack bs
	where hex n
		| n > 0xa   = showHex n ""
		| otherwise = "0" ++ showHex n ""

showDN dn = mapM_ (\(oid, (_,t)) -> putStrLn ("  " ++ show oid ++ ": " ++ t)) dn

showExts e = putStrLn $ show e

showCert :: X509.X509 -> IO ()
showCert (X509.X509 cert _ _ sigalg sigbits) = do
	putStrLn ("version: " ++ show (X509.certVersion cert))
	putStrLn ("serial:  " ++ show (X509.certSerial cert))
	putStrLn ("sigalg:  " ++ show (X509.certSignatureAlg cert))
	putStrLn "issuer:"
	showDN $ X509.certIssuerDN cert
	putStrLn "subject:"
	showDN $ X509.certSubjectDN cert
	putStrLn ("valid:  " ++ show (X509.certValidity cert))
	putStrLn ("pk:     " ++ show (X509.certPubKey cert))
	putStrLn "exts:"
	showExts $ X509.certExtensions cert
	putStrLn ("sigAlg: " ++ show sigalg)
	putStrLn ("sig:    " ++ show sigbits)


showRSAKey :: KeyRSA.Private -> String
showRSAKey key = unlines
	[ "version:          " ++ (show $ KeyRSA.version key)
	, "len-modulus:      " ++ (show $ KeyRSA.lenmodulus key)
	, "modulus:          " ++ (show $ KeyRSA.modulus key)
	, "public exponant:  " ++ (show $ KeyRSA.public_exponant key)
	, "private exponant: " ++ (show $ KeyRSA.private_exponant key)
	, "p1:               " ++ (show $ KeyRSA.p1 key)
	, "p2:               " ++ (show $ KeyRSA.p2 key)
	, "exp1:             " ++ (show $ KeyRSA.exp1 key)
	, "exp2:             " ++ (show $ KeyRSA.exp2 key)
	, "coefficient:      " ++ (show $ KeyRSA.coef key)
	]

showDSAKey :: KeyDSA.Private -> String
showDSAKey key = unlines
	[ "version: " ++ (show $ KeyDSA.version key)
	, "priv     " ++ (show $ KeyDSA.priv key)
	, "pub:     " ++ (show $ KeyDSA.pub key)
	, "p:       " ++ (show $ KeyDSA.p key)
	, "q:       " ++ (show $ KeyDSA.q key)
	, "g:       " ++ (show $ KeyDSA.g key)
	]

showASN1 :: [ASN1] -> IO ()
showASN1 = prettyPrint 0 where
	indent n = putStr (replicate n ' ')

	prettyPrint n []                 = return ()
	prettyPrint n (x@(Start _) : xs) = indent n >> p x >> putStrLn "" >> prettyPrint (n+1) xs
	prettyPrint n (x@(End _) : xs)   = indent (n-1) >> p x >> putStrLn "" >> prettyPrint (n-1) xs
	prettyPrint n (x : xs)           = indent n >> p x >> putStrLn "" >> prettyPrint n xs

	p (Boolean b)            = putStr ("bool: " ++ show b)
	p (IntVal i)             = putStr ("int: " ++ showHex i "")
	p (BitString i bs)       = putStr ("bitstring: " ++ hexdump bs)
	p (OctetString bs)       = putStr ("octetstring: " ++ hexdump bs)
	p (Null)                 = putStr "null"
	p (OID is)               = putStr ("OID: " ++ show is)
	p (Real d)               = putStr "real"
	p (Enumerated)           = putStr "enum"
	p (UTF8String t)         = putStr ("utf8string:" ++ t)
	p (Start Sequence)       = putStr "sequence"
	p (End Sequence)         = putStr "end-sequence"
	p (Start Set)            = putStr "set"
	p (End Set)              = putStr "end-set"
	p (Start _)              = putStr "container"
	p (End _)                = putStr "end-container"
	p (NumericString bs)     = putStr "numericstring:"
	p (PrintableString t)    = putStr ("printablestring: " ++ t)
	p (T61String bs)         = putStr "t61string:"
	p (VideoTexString bs)    = putStr "videotexstring:"
	p (IA5String bs)         = putStr "ia5string:"
	p (UTCTime time)         = putStr ("utctime: " ++ show time)
	p (GeneralizedTime time) = putStr ("generalizedtime: " ++ show time)
	p (GraphicString bs)     = putStr "graphicstring:"
	p (VisibleString bs)     = putStr "visiblestring:"
	p (GeneralString bs)     = putStr "generalstring:"
	p (UniversalString t)    = putStr ("universalstring:" ++ t)
	p (CharacterString bs)   = putStr "characterstring:"
	p (BMPString t)          = putStr ("bmpstring: " ++ t)
	p (Other tc tn x)        = putStr "other"

doMain :: CertMainOpts -> IO ()
doMain opts@(X509 _ _ _ _ _) = do
	cert <- maybe (error "cannot read PEM certificate") (id) . parsePEMCert <$> B.readFile (head $ files opts)

	when (raw opts) $ putStrLn $ hexdump $ L.fromChunks [cert]
	when (asn1 opts) $ case decodeASN1Stream $ L.fromChunks [cert] of
		Left err   -> error ("decoding ASN1 failed: " ++ show err)
		Right asn1 -> showASN1 asn1

	let x509o = X509.decodeCertificate $ L.fromChunks [cert]
	let x509  = case x509o of
		Left err   -> error ("decoding certificate failed: " ++ show err)
		Right c    -> c
	when (text opts || not (or [asn1 opts,raw opts])) $ showCert x509
	when (verify opts) $ verifyCert x509
	exitSuccess
	where
		verifyCert x509@(X509.X509 cert _ _ sigalg sig) = do
			sysx509 <- SysCert.findCertificate (matchsysX509 cert)
			case sysx509 of
				Nothing                        -> putStrLn "couldn't find signing certificate"
				Just (X509.X509 syscert _ _ _ _) -> do
					verifyAlg (B.concat $ L.toChunks $ X509.getSigningData x509)
					          (B.pack sig)
					          sigalg
					          (X509.certPubKey syscert)

		rsaVerify h hdesc pk a b = either (Left . show) (Right) $ RSA.verify h hdesc pk a b

		verifyF X509.SignatureALG_md2WithRSAEncryption (X509.PubKeyRSA rsak) = rsaVerify MD2.hash asn1 (mkRSA rsak)
			where asn1 = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x02\x10"

		verifyF X509.SignatureALG_md5WithRSAEncryption (X509.PubKeyRSA rsak) = rsaVerify MD5.hash asn1 (mkRSA rsak)
			where asn1 = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10"

		verifyF X509.SignatureALG_sha1WithRSAEncryption (X509.PubKeyRSA rsak) = rsaVerify SHA1.hash asn1 (mkRSA rsak)
			where asn1 = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"

		verifyF X509.SignatureALG_dsaWithSHA1 (X509.PubKeyDSA (pub,p,q,g)) =
			(\_ _ -> Left "unimplemented DSA checking")

		verifyF _ _ =
			(\_ _ -> Left "unexpected/wrong signature")

		mkRSA (lenmodulus, modulus, e) =
			RSA.PublicKey { RSA.public_sz = lenmodulus, RSA.public_n = modulus, RSA.public_e = e }

		verifyAlg toSign expectedSig sigalg pk =
			let f = verifyF sigalg pk in
			case f toSign expectedSig of
				Left err    -> putStrLn ("certificate couldn't be verified: something happened: " ++ show err)
				Right True  -> putStrLn "certificate verified"
				Right False -> putStrLn "certificate not verified"

		matchsysX509 cert (X509.X509 syscert _ _ _ _) = do
			let x = X509.certSubjectDN syscert
			let y = X509.certIssuerDN cert
			x == y
	
doMain (Key files) = do
	content <- B.readFile $ head files
	let pems = parsePEMs content
	let rsadata = findPEM "RSA PRIVATE KEY" pems
	let dsadata = findPEM "DSA PRIVATE KEY" pems
	case (rsadata, dsadata) of
		(Just x, _) -> do
			let rsaKey = KeyRSA.decodePrivate $ L.fromChunks [x]
			case rsaKey of
				Left err   -> error err
				Right k -> putStrLn $ showRSAKey k
		(_, Just x) -> do
			let rsaKey = KeyDSA.decodePrivate $ L.fromChunks [x]
			case rsaKey of
				Left err   -> error err
				Right k -> putStrLn $ showDSAKey k
		_ -> do
			putStrLn "no recognized private key found"

data CertMainOpts =
	  X509
		{ files  :: [FilePath]
		, asn1   :: Bool
		, text   :: Bool
		, raw    :: Bool
		, verify :: Bool
		}
	| Key
		{ files :: [FilePath]
		}
	deriving (Show,Data,Typeable)

x509Opts = X509
	{ files  = def &= args &= typFile
	, asn1   = def
	, text   = def
	, raw    = def
	, verify = def
	} &= help "x509 certificate related commands"

keyOpts = Key
	{ files = def &= args &= typFile
	} &= help "keys related commands"

mode = cmdArgsMode $ modes [x509Opts,keyOpts]
	&= help "create, manipulate certificate (x509,etc) and keys"
	&= program "certificate"
	&= summary "certificate v0.1"

main = cmdArgsRun mode >>= doMain
