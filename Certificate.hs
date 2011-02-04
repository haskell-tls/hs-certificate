{-# LANGUAGE DeriveDataTypeable #-}

import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString as B
import qualified Data.Text.Lazy as T
import Data.Text.Lazy.Encoding (decodeUtf8)
import Data.Certificate.X509
import Data.Certificate.KeyRSA as KeyRSA
import Data.Certificate.KeyDSA as KeyDSA
import Data.Certificate.PEM
import System.Console.CmdArgs
import Control.Monad
import Control.Applicative ((<$>))
import Data.Maybe
import System.Exit

import Data.ASN1.DER (decodeASN1Stream, ASN1(..), ASN1ConstructionType(..))
import Numeric

hexdump :: L.ByteString -> String
hexdump bs = concatMap hex $ L.unpack bs
	where hex n
		| n > 0xa   = showHex n ""
		| otherwise = "0" ++ showHex n ""

showDN dn = mapM_ (\(oid, (_,t)) -> putStrLn ("  " ++ show oid ++ ": " ++ T.unpack t)) dn

showExts e = putStrLn $ show e

showCert :: Certificate -> IO ()
showCert cert = do
	putStrLn ("version: " ++ show (certVersion cert))
	putStrLn ("serial:  " ++ show (certSerial cert))
	putStrLn ("sigalg:  " ++ show (certSignatureAlg cert))
	putStrLn "issuer:"
	showDN $ certIssuerDN cert
	putStrLn "subject:"
	showDN $ certSubjectDN cert
	putStrLn ("valid:  " ++ show (certValidity cert))
	putStrLn ("pk:     " ++ show (certPubKey cert))
	putStrLn "exts:"
	showExts $ certExtensions cert
	putStrLn ("sig:    " ++ show (certSignature cert))
	putStrLn ("other:  " ++ show (certOthers cert))


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
	p (UTF8String t)         = putStr ("utf8string:" ++ T.unpack t)
	p (Start Sequence)       = putStr "sequence"
	p (End Sequence)         = putStr "end-sequence"
	p (Start Set)            = putStr "set"
	p (End Set)              = putStr "end-set"
	p (Start _)              = putStr "container"
	p (End _)                = putStr "end-container"
	p (NumericString bs)     = putStr "numericstring:"
	p (PrintableString t)    = putStr ("printablestring: " ++ T.unpack t)
	p (T61String bs)         = putStr "t61string:"
	p (VideoTexString bs)    = putStr "videotexstring:"
	p (IA5String bs)         = putStr "ia5string:"
	p (UTCTime time)         = putStr ("utctime: " ++ show time)
	p (GeneralizedTime time) = putStr ("generalizedtime: " ++ show time)
	p (GraphicString bs)     = putStr "graphicstring:"
	p (VisibleString bs)     = putStr "visiblestring:"
	p (GeneralString bs)     = putStr "generalstring:"
	p (UniversalString t)    = putStr ("universalstring:" ++ T.unpack t)
	p (CharacterString bs)   = putStr "characterstring:"
	p (BMPString t)          = putStr ("bmpstring: " ++ T.unpack t)
	p (Other tc tn x)        = putStr "other"

doMain :: CertMainOpts -> IO ()
doMain opts@(X509 _ _ _ _) = do
	cert <- maybe (error "cannot read PEM certificate") (id) . parsePEMCert <$> B.readFile (head $ files opts)

	when (raw opts) $ putStrLn $ hexdump $ L.fromChunks [cert]
	when (asn1 opts) $ case decodeASN1Stream $ L.fromChunks [cert] of
		Left err   -> error ("decoding ASN1 failed: " ++ show err)
		Right asn1 -> showASN1 asn1
	when (text opts || not (or [asn1 opts,raw opts])) $ case decodeCertificate $ L.fromChunks [cert] of
		Left err   -> error ("decoding certificate failed: " ++ show err)
		Right c    -> showCert c
	exitSuccess
	
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
		{ files :: [FilePath]
		, asn1  :: Bool
		, text  :: Bool
		, raw   :: Bool
		}
	| Key
		{ files :: [FilePath]
		}
	deriving (Show,Data,Typeable)

x509Opts = X509
	{ files = def &= args &= typFile
	, asn1  = def
	, text  = def
	, raw   = def
	} &= help "x509 certificate related commands"

keyOpts = Key
	{ files = def &= args &= typFile
	} &= help "keys related commands"

mode = cmdArgsMode $ modes [x509Opts,keyOpts]
	&= help "create, manipulate certificate (x509,etc) and keys"
	&= program "certificate"
	&= summary "certificate v0.1"

main = cmdArgsRun mode >>= doMain
