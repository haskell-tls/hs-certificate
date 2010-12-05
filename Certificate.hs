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

readprivate :: FilePath -> IO (Either String PrivateKey)
readprivate file = B.readFile file >>= return . maybe (Left "no valid private RSA key found") (decodePrivateKey . L.fromChunks . (:[])) . parsePEMKeyRSA

hexdump :: L.ByteString -> String
hexdump bs = concatMap hex $ L.unpack bs
	where hex n
		| n > 0xa   = showHex n ""
		| otherwise = "0" ++ showHex n ""

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
		"p1:               " ++ (show $ privKey_p1 key),
		"p2:               " ++ (show $ privKey_p2 key),
		"exp1:             " ++ (show $ privKey_exp1 key),
		"exp2:             " ++ (show $ privKey_exp2 key),
		"coefficient:      " ++ (show $ privKey_coef key)
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
	p _ (UTF8String bs)        = putStr ("utf8string:" ++ T.unpack (decodeUtf8 bs))
	p l (Sequence o)           = putStrLn "sequence" >> mapM_ (prettyPrint (l+1)) o >> indent l >> putStr "end-sequence"
	p l (Set o)                = putStrLn "set" >> mapM_ (prettyPrint (l+1)) o >> indent l >> putStr "end-set"
	p _ (NumericString bs)     = putStr "numericstring:"
	p _ (PrintableString bs)   = putStr ("printablestring: " ++ LC.unpack bs)
	p _ (T61String bs)         = putStr "t61string:"
	p _ (VideoTexString bs)    = putStr "videotexstring:"
	p _ (IA5String bs)         = putStr "ia5string:"
	p _ (UTCTime time)         = putStr ("utctime: " ++ show time)
	p _ (GeneralizedTime time) = putStr ("generalizedtime: " ++ show time)
	p _ (GraphicString bs)     = putStr "graphicstring:"
	p _ (VisibleString bs)     = putStr "visiblestring:"
	p _ (GeneralString bs)     = putStr "generalstring:"
	p _ (UniversalString bs)   = putStr "universalstring:"
	p _ (CharacterString bs)   = putStr "characterstring:"
	p _ (BMPString bs)         = putStr "bmpstring:"
	p l (Other tc tn x)        = putStr "other:"

mainX509 :: CertMainOpts -> IO ()
mainX509 opts = do
	cert <- maybe (error "cannot read PEM certificate") (id) . parsePEMCert <$> B.readFile (head $ files opts)

	when (raw opts) $ putStrLn $ hexdump $ L.fromChunks [cert]
	when (asn1 opts) $ case decodeASN1 $ L.fromChunks [cert] of
		Left err   -> error ("decoding ASN1 failed: " ++ show err)
		Right asn1 -> showASN1 asn1
	when (text opts || not (or [asn1 opts,raw opts])) $ case decodeCertificate $ L.fromChunks [cert] of
		Left err   -> error ("decoding certificate failed: " ++ show err)
		Right c    -> putStrLn $ showCert c
	exitSuccess
	
mainKey :: CertMainOpts -> IO ()
mainKey opts = do
	c <- readprivate $ head $ files opts
	case c of
		Left err   -> error err
		Right cert -> putStrLn $ showKey cert

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
	, asn1 = def
	, text = def
	, raw = def
	} &= help "x509 certificate related commands"

keyOpts = Key
	{ files = def &= args &= typFile
	} &= help "keys related commands"

mode = cmdArgsMode $ modes [x509Opts,keyOpts]
	&= help "create, manipulate certificate (x509,etc) and keys" &= program "certificate" &= summary "certificate v0.1"

main = do
	x <- cmdArgsRun mode
	case x of
		X509 _ _ _ _ -> mainX509 x
		Key  _ -> mainKey x
