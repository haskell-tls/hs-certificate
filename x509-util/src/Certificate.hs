{-# LANGUAGE DeriveDataTypeable, OverloadedStrings #-}

import Data.Either
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString as B
import Data.X509
import qualified Data.X509 as X509
import Data.List (find)
import Data.PEM (pemParseBS, pemContent, pemName)
import System.Console.GetOpt
import System.Environment
import Control.Monad
import Control.Applicative ((<$>))
import Data.Maybe
import System.Exit
import System.X509
import Data.X509.CertificateStore
import Data.X509.Validation
import Data.Hourglass

-- for signing/verifying certificate
import Crypto.Hash
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.DSA as DSA

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import Data.ASN1.BitArray
import Data.X509.Memory
import Text.Printf
import Numeric

formatValidity (start,end) = p start ++ " to " ++ p end
  where p t = timePrint ("YYYY-MM-DD H:MI:S" :: String) t

hexdump :: B.ByteString -> String
hexdump bs = concatMap hex $ B.unpack bs
    where hex n
            | n > 0xf   = showHex n ""
            | otherwise = "0" ++ showHex n ""

hexdump' = hexdump

showDN (X509.DistinguishedName dn) = mapM_ toStr dn
  where toStr (oid, cs@(ASN1CharacterString e t)) =
            putStrLn ("  " ++ key ++ ": " ++ value)
          where key = show oid
                value = case asn1CharacterToString cs of
                            Nothing -> show e ++ " " ++ show t ++ " (decoding to string failed)"
                            Just s  -> show s ++ " (encoding : " ++ show e ++ ")"

showExts es@(Extensions Nothing) = do
    return ()
showExts es@(Extensions (Just exts)) = do
    mapM_ showExt exts
    putStrLn "known extensions decoded: "
    showKnownExtension "basic-constraint" (X509.extensionGetE es :: Maybe (Either String X509.ExtBasicConstraints))
    showKnownExtension "key-usage" (X509.extensionGetE es :: Maybe (Either String X509.ExtKeyUsage))
    showKnownExtension "extended-key-usage" (X509.extensionGetE es :: Maybe (Either String X509.ExtExtendedKeyUsage))
    showKnownExtension "subject-key-id" (X509.extensionGetE es :: Maybe (Either String X509.ExtSubjectKeyId))
    showKnownExtension "subject-alt-name" (X509.extensionGetE es :: Maybe (Either String X509.ExtSubjectAltName))
    showKnownExtension "authority-key-id" (X509.extensionGetE es :: Maybe (Either String X509.ExtAuthorityKeyId))
    where
        showExt (ExtensionRaw oid critical asn1) = do
            putStrLn ("  OID:  " ++ show oid ++ " critical: " ++ show critical)
            showASN1 8 asn1
        showKnownExtension _ Nothing  = return ()
        showKnownExtension n (Just (Left e)) = putStrLn ("  " ++ n ++ ": ERROR: " ++ show e)
        showKnownExtension _ (Just (Right e)) = putStrLn ("  " ++ show e)

showCertSmall :: SignedCertificate -> IO ()
showCertSmall signedCert = do
    putStrLn "subject: "
    showDN $ X509.certSubjectDN cert
    putStrLn ("valid:  " ++ formatValidity (X509.certValidity cert))
    case X509.certPubKey cert of
        X509.PubKeyRSA pubkey     -> printf "public key: RSA (%d bits)\n" (RSA.public_size pubkey * 8)
        X509.PubKeyDSA pubkey     -> printf "public key: DSA\n"
        X509.PubKeyUnknown oid ws -> printf "public key: unknown: %s\n" (show oid)
        pk                        -> printf "public key: %s\n" (show pk)
  where
    signed  = X509.getSigned signedCert
    --sigalg  = X509.signedAlg signed
    --sigbits = X509.signedSignature signed
    cert    = X509.signedObject signed

showCert :: SignedCertificate -> IO ()
showCert signedCert = do
    putStrLn ("version: " ++ show (X509.certVersion cert))
    putStrLn ("serial:  " ++ show (X509.certSerial cert))
    putStrLn ("sigalg:  " ++ show (X509.certSignatureAlg cert))
    putStrLn "issuer:"
    showDN $ X509.certIssuerDN cert
    putStrLn "subject:"
    showDN $ X509.certSubjectDN cert
    putStrLn ("valid:  " ++ formatValidity (X509.certValidity cert))
    case X509.certPubKey cert of
        X509.PubKeyRSA pubkey -> do
            putStrLn "public key RSA:"
            printf "  len    : %d bits\n" (RSA.public_size pubkey * 8)
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
        pk                        ->
            printf "public key: %s\n" (show pk)
    case X509.certExtensions cert of
        (Extensions Nothing)   -> return ()
        (Extensions (Just es)) -> putStrLn "extensions:" >> showExts (X509.certExtensions cert)
    putStrLn ("sigAlg: " ++ show sigalg)
    putStrLn ("sig:    " ++ show sigbits)
  where
    signed  = X509.getSigned signedCert
    sigalg  = X509.signedAlg signed
    sigbits = X509.signedSignature signed
    cert    = X509.signedObject signed


showRSAKey :: RSA.PrivateKey -> String
showRSAKey privkey = unlines
    [ "len-modulus:      " ++ (show $ RSA.public_size pubkey)
    , "modulus:          " ++ (show $ RSA.public_n pubkey)
    , "public exponent:  " ++ (show $ RSA.public_e pubkey)
    , "private exponent: " ++ (show $ RSA.private_d privkey)
    , "p1:               " ++ (show $ RSA.private_p privkey)
    , "p2:               " ++ (show $ RSA.private_q privkey)
    , "exp1:             " ++ (show $ RSA.private_dP privkey)
    , "exp2:             " ++ (show $ RSA.private_dQ privkey)
    , "coefficient:      " ++ (show $ RSA.private_qinv privkey)
    ]
  where pubkey = RSA.private_pub privkey

showDSAKey :: DSA.PrivateKey -> String
showDSAKey (DSA.PrivateKey params privnum) = unlines
    [ "priv     " ++ (printf "%x" $ privnum)
    , "p:       " ++ (printf "%x" $ DSA.params_p params)
    , "q:       " ++ (printf "%x" $ DSA.params_q params)
    , "g:       " ++ (printf "%x" $ DSA.params_g params)
    ]

showASN1 :: Int -> [ASN1] -> IO ()
showASN1 at = prettyPrint at
  where
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
    p (Enumerated _)         = putStr "enum"
    p (Start Sequence)       = putStr "{"
    p (End Sequence)         = putStr "}"
    p (Start Set)            = putStr "["
    p (End Set)              = putStr "]"
    p (Start (Container x y)) = putStr ("< " ++ show x ++ " " ++ show y)
    p (End (Container x y))   = putStr ("> " ++ show x ++ " " ++ show y)
    p (ASN1String cs)        = putCS cs
    p (ASN1Time TimeUTC time tz)      = putStr ("utctime: " ++ show time)
    p (ASN1Time TimeGeneralized time tz) = putStr ("generalizedtime: " ++ show time)
    p (Other tc tn x)        = putStr ("other(" ++ show tc ++ "," ++ show tn ++ ")")

    putCS (ASN1CharacterString UTF8 t)         = putStr ("utf8string:" ++ show t)
    putCS (ASN1CharacterString Numeric bs)     = putStr "numericstring:"
    putCS (ASN1CharacterString Printable t)    = putStr ("printablestring: " ++ show t)
    putCS (ASN1CharacterString T61 bs)         = putStr ("t61string:" ++ show bs)
    putCS (ASN1CharacterString VideoTex bs)    = putStr "videotexstring:"
    putCS (ASN1CharacterString IA5 bs)         = putStr ("ia5string:" ++ show bs)
    putCS (ASN1CharacterString Graphic bs)     = putStr "graphicstring:"
    putCS (ASN1CharacterString Visible bs)     = putStr "visiblestring:"
    putCS (ASN1CharacterString General bs)     = putStr "generalstring:"
    putCS (ASN1CharacterString UTF32 t)        = putStr ("universalstring:" ++ show t)
    putCS (ASN1CharacterString Character bs)   = putStr "characterstring:"
    putCS (ASN1CharacterString BMP t)          = putStr ("bmpstring: " ++ show t)

data X509Opts =
      DumpedRaw
    | DumpedText
    | ShowHash
    | Validate
    | ValidationHost String
    | Help
    deriving (Show,Eq)

readPEMFile file = do
    content <- B.readFile file
    return $ either error id $ pemParseBS content

readSignedObject file = do
    content <- B.readFile file
    return $ either error (map (X509.decodeSignedObject . pemContent)) $ pemParseBS content

doCertMain opts files = do
    when (Help `elem` opts) $ do
        putStrLn $ usageInfo "usage: x509-util cert [options] <certificates>" optionsCert
        exitSuccess
    objs <- readSignedObject (head files)
    forM_ objs $ \o ->
        case o of
            Left err     -> error ("decoding Certificate failed: " ++ show err)
            Right signed -> do
                showCert signed
                when (ShowHash `elem` opts) $ hashCert signed
    when (Validate `elem` opts) $ do
        let cc = CertificateChain (rights objs)
        store  <- getSystemCertificateStore
        failed <- validate HashSHA1 defaultHooks validationChecks store (exceptionValidationCache [])
                        (maybe ("", "") (\f -> (f,"")) fqhn) cc
        if failed /= []
            then putStrLn ("validation failed: " ++ show failed)
            else putStrLn "validation success"
  where
        hashCert signedCert = do
            putStrLn ("subject(MD5) old: " ++ hexdump' (X509.hashDN_old subject))
            putStrLn ("issuer(MD5) old:  " ++ hexdump' (X509.hashDN_old issuer))
            putStrLn ("subject(SHA1):    " ++ hexdump' (X509.hashDN subject))
            putStrLn ("issuer(SHA1):     " ++ hexdump' (X509.hashDN issuer))
            where
                subject = X509.certSubjectDN cert
                issuer  = X509.certIssuerDN cert
                cert    = X509.signedObject $ X509.getSigned signedCert
        validationChecks = defaultChecks { checkExhaustive = True, checkFQHN = isJust fqhn }
        fqhn = foldl accHost Nothing opts
        accHost Nothing (ValidationHost h) = Just h
        accHost a       _                  = a

doCRLMain opts files = do
    readSignedObject (head files) >>= \objs -> forM_ objs $ \o ->
        case o of
            Left err     -> error ("decoding CRL failed: " ++ show err)
            Right signed -> do
                putStrLn $ show $ getCRL signed

doASN1Main files = do
    pem <- readPEMFile (head files)
    forM_ pem $ \p ->
        case decodeASN1' BER $ pemContent p of
            Left err   -> error ("decoding ASN1 failed: " ++ show err)
            Right asn1 -> showASN1 0 asn1
    
doKeyMain files = do
    pems <- readPEMFile (head files)
    forM_ pems $ \pem -> do
        let content = either (error . show) id $ decodeASN1' BER (pemContent pem)
            privkey = catMaybes $ pemToKey [] pem
        case privkey of
            [X509.PrivKeyRSA k] ->
                putStrLn "RSA KEY" >> putStrLn (showRSAKey k)
            [X509.PrivKeyDSA k] ->
                putStrLn "DSA KEY" >> putStrLn (showDSAKey k)
            _ -> error "private key unknown"

doSystemMain _ = do
    store <- getSystemCertificateStore
    let certs = listCertificates store
    mapM_ showCertSmall certs
    putStrLn $ replicate 72 '='
    putStrLn $ show (length certs) ++ " certificates loaded"

optionsCert =
    [ Option []     ["hash"] (NoArg ShowHash) "output certificate hash"
    , Option ['v']  ["validate"] (NoArg Validate) "validate certificate"
    , Option []     ["validation-host"] (ReqArg ValidationHost "host") "validation host use for validation"
    , Option ['h']  ["help"] (NoArg Help) "show help"
    ]

certMain = getoptMain optionsCert $ \o n -> doCertMain o n
crlMain = getoptMain [] $ \o n -> doCRLMain o n
keyMain = getoptMain [] $ \o n -> doKeyMain n
asn1Main = getoptMain [] $ \o n -> doASN1Main n

systemMain = getoptMain [] $ \o n -> doSystemMain n


getoptMain :: [OptDescr a] -> ([a] -> [String] -> IO ()) -> [String] -> IO ()
getoptMain opts f as =
    case getOpt Permute opts as of
        (o,n,[])  -> f o n
        (_,_,err) -> error (show err)

usage = do
    putStrLn "usage: x509-util <cmd>"
    putStrLn "  key : process private key"
    putStrLn "  cert: process X509 certificate"
    putStrLn "  crl : process CRL certificate"
    putStrLn "  asn1: show file asn1"
    putStrLn "  system: show system certificates"

main = do
    args <- getArgs
    case args of
        []        -> usage
        "x509":as -> certMain as
        "cert":as -> certMain as
        "key":as  -> keyMain as
        "crl":as  -> crlMain as
        "asn1":as -> asn1Main as
        "system":as -> systemMain as
        _         -> usage
