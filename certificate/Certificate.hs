{-# LANGUAGE DeriveDataTypeable, OverloadedStrings #-}

import Data.Either
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString as B
import qualified Data.Text.Lazy as T
import Data.Text.Lazy.Encoding (decodeUtf8)
import qualified Data.Certificate.X509 as X509
import Data.Certificate.X509.Cert as Cert
import Data.Certificate.KeyRSA as KeyRSA
import Data.Certificate.KeyDSA as KeyDSA
import Data.List (find)
import Data.PEM (pemParseBS, pemContent, pemName)
import System.Console.CmdArgs
import Control.Monad
import Control.Applicative ((<$>))
import Data.Maybe
import System.Exit
import System.Certificate.X509
import Data.CertificateStore

-- for signing/verifying certificate
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA224 as SHA224
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.MD2 as MD2
import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.PubKey.HashDescr as HD
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.DSA as DSA

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Stream
import Data.ASN1.BitArray
import Text.Printf
import Numeric

hexdump :: L.ByteString -> String
hexdump bs = concatMap hex $ L.unpack bs
	where hex n
		| n > 0xa   = showHex n ""
		| otherwise = "0" ++ showHex n ""

hexdump' :: B.ByteString -> String
hexdump' = hexdump . L.fromChunks . (:[])

showDN (X509.DistinguishedName dn) = mapM_ (\(oid, (_,t)) -> putStrLn ("  " ++ show oid ++ ": " ++ t)) dn

showExts es = do
	mapM_ showExt es
	putStrLn "known extensions decoded: "
	showKnownExtension (X509.extensionGet es :: Maybe X509.ExtBasicConstraints)
	showKnownExtension (X509.extensionGet es :: Maybe X509.ExtKeyUsage)
	showKnownExtension (X509.extensionGet es :: Maybe X509.ExtSubjectKeyId)
	showKnownExtension (X509.extensionGet es :: Maybe X509.ExtSubjectAltName)
	showKnownExtension (X509.extensionGet es :: Maybe X509.ExtAuthorityKeyId)
	where
		showExt (oid,critical,asn1) = do
			putStrLn ("  OID:  " ++ show oid ++ " critical: " ++ show critical)
			putStrLn ("        " ++ show asn1)
		showKnownExtension Nothing  = return ()
		showKnownExtension (Just e) = putStrLn ("  " ++ show e)

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
	case X509.certPubKey cert of
		X509.PubKeyRSA pubkey -> do
			putStrLn "public key RSA:"
			printf "  len    : %d\n" (RSA.public_size pubkey)
			printf "  modulus: %x\n" (RSA.public_n pubkey)
			printf "  e      : %x\n" (RSA.public_e pubkey)
		X509.PubKeyDSA pubkey -> do
			let params = DSA.public_params pubkey
			putStrLn "public key DSA:"
			printf "  pub    : %x\n" (DSA.public_y pubkey)
			printf "  p      : %d\n" (DSA.params_p params)
			printf "  q      : %x\n" (DSA.params_q params)
			printf "  g      : %x\n" (DSA.params_g params)
		X509.PubKeyUnknown oid ws -> do
			printf "public key unknown: %s\n" (show oid)
			printf "  raw bytes: %s\n" (show ws)
			case decodeASN1 BER $ L.pack ws of
				Left err -> printf "  asn1 decoding failed: %s\n" (show err)
				Right l  -> printf "  asn1 decoding:\n" >> showASN1 4 l
		pk                        ->
			printf "public key: %s\n" (show pk)
	case X509.certExtensions cert of
		Nothing -> return ()
		Just es -> do
			putStrLn "extensions:"
			showExts es
	putStrLn ("sigAlg: " ++ show sigalg)
	putStrLn ("sig:    " ++ show sigbits)


showRSAKey :: (RSA.PublicKey,RSA.PrivateKey) -> String
showRSAKey (pubkey,privkey) = unlines
	[ "len-modulus:      " ++ (show $ RSA.public_size pubkey)
	, "modulus:          " ++ (show $ RSA.public_n pubkey)
	, "public exponant:  " ++ (show $ RSA.public_e pubkey)
	, "private exponant: " ++ (show $ RSA.private_d privkey)
	, "p1:               " ++ (show $ RSA.private_p privkey)
	, "p2:               " ++ (show $ RSA.private_q privkey)
	, "exp1:             " ++ (show $ RSA.private_dP privkey)
	, "exp2:             " ++ (show $ RSA.private_dQ privkey)
	, "coefficient:      " ++ (show $ RSA.private_qinv privkey)
	]

showDSAKey :: (DSA.PublicKey,DSA.PrivateKey) -> String
showDSAKey (pubkey,privkey) = unlines
	[ "priv     " ++ (printf "%x" $ DSA.private_x privkey)
	, "pub:     " ++ (printf "%x" $ DSA.public_y pubkey)
	, "p:       " ++ (printf "%x" $ DSA.params_p params)
	, "q:       " ++ (printf "%x" $ DSA.params_q params)
	, "g:       " ++ (printf "%x" $ DSA.params_g params)
	]
    where params = DSA.private_params privkey

showASN1 :: Int -> [ASN1] -> IO ()
showASN1 at = prettyPrint at where
	indent n = putStr (replicate n ' ')

	prettyPrint n []                 = return ()
	prettyPrint n (x@(Start _) : xs) = indent n >> p x >> putStrLn "" >> prettyPrint (n+1) xs
	prettyPrint n (x@(End _) : xs)   = indent (n-1) >> p x >> putStrLn "" >> prettyPrint (n-1) xs
	prettyPrint n (x : xs)           = indent n >> p x >> putStrLn "" >> prettyPrint n xs

	p (Boolean b)            = putStr ("bool: " ++ show b)
	p (IntVal i)             = putStr ("int: " ++ showHex i "")
	p (BitString bits)       = putStr ("bitstring: " ++ (hexdump $ bitArrayGetData bits))
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

parsePEMCert = either (const []) (rights . map getCert) . pemParseBS
    where getCert pem = either Left (\x -> Right (pemContent pem,x)) $ X509.decodeCertificate $ L.fromChunks [pemContent pem]

processCert opts (cert, x509) = do
	when (raw opts) $ putStrLn $ hexdump $ L.fromChunks [cert]
	when (asn1 opts) $ case decodeASN1' BER cert of
		Left err   -> error ("decoding ASN1 failed: " ++ show err)
		Right asn1 -> showASN1 0 asn1

	when (text opts || not (or [asn1 opts,raw opts])) $ showCert x509
	when (hash opts) $ hashCert x509
	when (verify opts) $ getSystemCertificateStore >>= flip verifyCert x509
	where
		hashCert x509@(X509.X509 cert _ _ _ _) = do
			putStrLn ("subject(MD5):  " ++ hexdump' (X509.hashDN_old subject))
			putStrLn ("issuer(MD5):   " ++ hexdump' (X509.hashDN_old issuer))
			putStrLn ("subject(SHA1): " ++ hexdump' (X509.hashDN subject))
			putStrLn ("issuer(SHA1):  " ++ hexdump' (X509.hashDN issuer))
			where
				subject    = X509.certSubjectDN cert
				issuer     = X509.certIssuerDN cert
		verifyCert store x509@(X509.X509 cert _ _ sigalg sig) = do
			case findCertificate (X509.certIssuerDN cert) store of
				Nothing                        -> putStrLn "couldn't find signing certificate"
				Just (X509.X509 syscert _ _ _ _) -> do
					verifyAlg (B.concat $ L.toChunks $ X509.getSigningData x509)
					          (B.pack sig)
					          sigalg
					          (X509.certPubKey syscert)

		rsaVerify hdesc pk a b = Right $ RSA.verify hdesc pk a b

		verifyF (X509.SignatureALG hash X509.PubKeyALG_RSA) (X509.PubKeyRSA rsak) =
			let hdesc = case hash of
				-- "ASN.1 DER X algorithm designator prefix"
				X509.HashMD2    -> HD.hashDescrMD2
				X509.HashMD5    -> HD.hashDescrMD5
				X509.HashSHA1   -> HD.hashDescrSHA1
				X509.HashSHA224 -> HD.hashDescrSHA224
				X509.HashSHA256 -> HD.hashDescrSHA256
				X509.HashSHA384 -> HD.hashDescrSHA384
				X509.HashSHA512 -> HD.hashDescrSHA512
				_               -> error ("unsupported hash in RSA: " ++ show hash)
				in
			rsaVerify hdesc rsak

		verifyF (X509.SignatureALG _ X509.PubKeyALG_DSA) (X509.PubKeyDSA dsak) =
			(\_ _ -> Left "unimplemented DSA checking")

		verifyF _ _ =
			(\_ _ -> Left "unexpected/wrong signature")

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

doMain :: CertMainOpts -> IO ()
doMain opts@(X509 {}) = B.readFile (head $ files opts) >>= mapM_ (processCert opts) . parsePEMCert
	
doMain (Key files) = do
	pems <- either error id . pemParseBS <$> B.readFile (head files)
	let rsadata = find ((== "RSA PRIVATE KEY") . pemName) pems
	let dsadata = find ((== "DSA PRIVATE KEY") . pemName) pems
	case (rsadata, dsadata) of
		(Just x, _) -> do
			let rsaKey = KeyRSA.decodePrivate $ L.fromChunks [pemContent x]
			case rsaKey of
				Left err -> error err
				Right k  -> putStrLn $ showRSAKey k
		(_, Just x) -> do
			let rsaKey = KeyDSA.decodePrivate $ L.fromChunks [pemContent x]
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
		, hash   :: Bool
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
	, hash   = def
	} &= help "x509 certificate related commands"

keyOpts = Key
	{ files = def &= args &= typFile
	} &= help "keys related commands"

mode = cmdArgsMode $ modes [x509Opts,keyOpts]
	&= help "create, manipulate certificate (x509,etc) and keys"
	&= program "certificate"
	&= summary "certificate v0.1"

main = cmdArgsRun mode >>= doMain
