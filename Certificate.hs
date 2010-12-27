{-# LANGUAGE DeriveDataTypeable #-}

import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString as B
import qualified Data.Text.Lazy as T
import Data.Text.Lazy.Encoding (decodeUtf8)
import Data.Certificate.X509
import Data.Certificate.Key
import Data.Certificate.PEM
import System.Console.CmdArgs
import Control.Monad
import Control.Applicative ((<$>))
import Data.Maybe
import System.Exit

import Data.ASN1.DER
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


showKey :: PrivateRSAKey -> String
showKey key = unlines
	[ "version:          " ++ (show $ privRSAKey_version key)
	, "len-modulus:      " ++ (show $ privRSAKey_lenmodulus key)
	, "modulus:          " ++ (show $ privRSAKey_modulus key)
	, "public exponant:  " ++ (show $ privRSAKey_public_exponant key)
	, "private exponant: " ++ (show $ privRSAKey_private_exponant key)
	, "p1:               " ++ (show $ privRSAKey_p1 key)
	, "p2:               " ++ (show $ privRSAKey_p2 key)
	, "exp1:             " ++ (show $ privRSAKey_exp1 key)
	, "exp2:             " ++ (show $ privRSAKey_exp2 key)
	, "coefficient:      " ++ (show $ privRSAKey_coef key)
	]

showASN1 :: ASN1 -> IO ()
showASN1 = prettyPrint 0 where
	prettyPrint l a = indent l >> p l a >> putStrLn ""
	indent l        = putStr (replicate l ' ')
	p _ (EOC)                  = putStr ""
	p _ (Boolean b)            = putStr ("bool: " ++ show b)
	p _ (IntVal i)             = putStr ("int: " ++ showHex i "")
	p _ (BitString i bs)       = putStr ("bitstring: " ++ hexdump bs)
	p _ (OctetString bs)       = putStr ("octetstring: " ++ hexdump bs)
	p _ (Null)                 = putStr "null"
	p _ (OID is)               = putStr ("OID: " ++ show is) 
	p _ (Real d)               = putStr "real"
	p _ (Enumerated)           = putStr "enum"
	p _ (UTF8String t)         = putStr ("utf8string:" ++ T.unpack t)
	p l (Sequence o)           = putStrLn "sequence" >> mapM_ (prettyPrint (l+1)) o >> indent l >> putStr "end-sequence"
	p l (Set o)                = putStrLn "set" >> mapM_ (prettyPrint (l+1)) o >> indent l >> putStr "end-set"
	p _ (NumericString bs)     = putStr "numericstring:"
	p _ (PrintableString t)    = putStr ("printablestring: " ++ T.unpack t)
	p _ (T61String bs)         = putStr "t61string:"
	p _ (VideoTexString bs)    = putStr "videotexstring:"
	p _ (IA5String bs)         = putStr "ia5string:"
	p _ (UTCTime time)         = putStr ("utctime: " ++ show time)
	p _ (GeneralizedTime time) = putStr ("generalizedtime: " ++ show time)
	p _ (GraphicString bs)     = putStr "graphicstring:"
	p _ (VisibleString bs)     = putStr "visiblestring:"
	p _ (GeneralString bs)     = putStr "generalstring:"
	p _ (UniversalString t)    = putStr ("universalstring:" ++ T.unpack t)
	p _ (CharacterString bs)   = putStr "characterstring:"
	p _ (BMPString t)          = putStr ("bmpstring: " ++ T.unpack t)
	p l (Other tc tn x)        = putStr "other:"

doMain :: CertMainOpts -> IO ()
doMain opts@(X509 _ _ _ _) = do
	cert <- maybe (error "cannot read PEM certificate") (id) . parsePEMCert <$> B.readFile (head $ files opts)

	when (raw opts) $ putStrLn $ hexdump $ L.fromChunks [cert]
	when (asn1 opts) $ case decodeASN1 $ L.fromChunks [cert] of
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
			let rsaKey = decodePrivateRSAKey $ L.fromChunks [x]
			case rsaKey of
				Left err   -> error err
				Right k -> putStrLn $ showKey k
		(_, Just x) ->
			putStrLn "decoding DSA key not implemented"
		_ -> do
			putStrLn "no recognized private key found"

data CertMainOpts =
	  X509
		{ files :: [FilePath]
		, asn1 :: Bool
		, text :: Bool
		, raw :: Bool
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
