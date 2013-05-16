{-# LANGUAGE DeriveDataTypeable, OverloadedStrings #-}

import Data.Either
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString as B
import qualified Data.Text.Lazy as T
import Data.Text.Lazy.Encoding (decodeUtf8)
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

-- for signing/verifying certificate
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA224 as SHA224
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.MD2 as MD2
import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.PubKey.HashDescr as HD
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.Types.PubKey.RSA as RSA
import qualified Crypto.Types.PubKey.DSA as DSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.DSA as DSA

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import Data.ASN1.BitArray
import Text.Printf
import Numeric

hexdump :: B.ByteString -> String
hexdump bs = concatMap hex $ B.unpack bs
    where hex n
            | n > 0xa   = showHex n ""
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
    showKnownExtension (X509.extensionGet es :: Maybe X509.ExtBasicConstraints)
    showKnownExtension (X509.extensionGet es :: Maybe X509.ExtKeyUsage)
    showKnownExtension (X509.extensionGet es :: Maybe X509.ExtSubjectKeyId)
    showKnownExtension (X509.extensionGet es :: Maybe X509.ExtSubjectAltName)
    showKnownExtension (X509.extensionGet es :: Maybe X509.ExtAuthorityKeyId)
    where
        showExt (ExtensionRaw oid critical asn1) = do
            putStrLn ("  OID:  " ++ show oid ++ " critical: " ++ show critical)
            putStrLn ("        " ++ show asn1)
        showKnownExtension Nothing  = return ()
        showKnownExtension (Just e) = putStrLn ("  " ++ show e)

showCert :: SignedCertificate -> IO ()
showCert signedCert = do
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
            --case decodeASN1 BER $ L.pack ws of
            --    Left err -> printf "  asn1 decoding failed: %s\n" (show err)
            --    Right l  -> printf "  asn1 decoding:\n" >> showASN1 4 l
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


showRSAKey :: (RSA.KeyPair) -> String
showRSAKey (RSA.KeyPair privkey) = unlines
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
  where pubkey = RSA.private_pub privkey

showDSAKey :: DSA.KeyPair -> String
showDSAKey (DSA.KeyPair params pubnum privnum) = unlines
    [ "priv     " ++ (printf "%x" $ privnum)
    , "pub:     " ++ (printf "%x" $ pubnum)
    , "p:       " ++ (printf "%x" $ DSA.params_p params)
    , "q:       " ++ (printf "%x" $ DSA.params_q params)
    , "g:       " ++ (printf "%x" $ DSA.params_g params)
    ]

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
    p (Enumerated _)         = putStr "enum"
    p (Start Sequence)       = putStr "sequence"
    p (End Sequence)         = putStr "end-sequence"
    p (Start Set)            = putStr "set"
    p (End Set)              = putStr "end-set"
    p (Start _)              = putStr "container"
    p (End _)                = putStr "end-container"
    p (ASN1String cs)        = putCS cs
    p (ASN1Time TimeUTC time tz)      = putStr ("utctime: " ++ show time)
    p (ASN1Time TimeGeneralized time tz) = putStr ("generalizedtime: " ++ show time)
    p (Other tc tn x)        = putStr ("other(" ++ show tc ++ "," ++ show tn ++ ")")

    putCS (ASN1CharacterString UTF8 t)         = putStr ("utf8string:" ++ show t)
    putCS (ASN1CharacterString Numeric bs)     = putStr "numericstring:"
    putCS (ASN1CharacterString Printable t)    = putStr ("printablestring: " ++ show t)
    putCS (ASN1CharacterString T61 bs)         = putStr "t61string:"
    putCS (ASN1CharacterString VideoTex bs)    = putStr "videotexstring:"
    putCS (ASN1CharacterString IA5 bs)         = putStr "ia5string:"
    putCS (ASN1CharacterString Graphic bs)     = putStr "graphicstring:"
    putCS (ASN1CharacterString Visible bs)     = putStr "visiblestring:"
    putCS (ASN1CharacterString General bs)     = putStr "generalstring:"
    putCS (ASN1CharacterString UTF32 t)        = putStr ("universalstring:" ++ show t)
    putCS (ASN1CharacterString Character bs)   = putStr "characterstring:"
    putCS (ASN1CharacterString BMP t)          = putStr ("bmpstring: " ++ show t)

{-
    when (verify opts) $ getSystemCertificateStore >>= flip verifyCert x509
  where
        verifyCert store x509@(X509.X509 cert _ _ sigalg sig) = do
            case findCertificate (X509.certIssuerDN cert) store of
                Nothing                        -> putStrLn "couldn't find signing certificate"
                Just (X509.X509 syscert _ _ _ _) -> do
                    verifyAlg (B.concat $ L.toChunks $ X509.getSigningData x509)
                              (B.pack sig)
                              sigalg
                              (X509.certPubKey syscert)
-}

data X509Opts =
      DumpedRaw
    | DumpedText
    | ShowHash
    deriving (Show,Eq)

readPEMFile file = do
    content <- B.readFile file
    return $ either error id $ pemParseBS content

readSignedObject file = do
    content <- B.readFile file
    return $ either error (map (X509.decodeSignedObject . pemContent)) $ pemParseBS content

doCertMain opts files =
    readSignedObject (head files) >>= \objs -> forM_ objs $ \o ->
        case o of
            Left err     -> error ("decoding Certificate failed: " ++ show err)
            Right signed -> do
                showCert signed
                when (ShowHash `elem` opts) $ hashCert signed
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
        case pemName pem of
            "RSA PRIVATE KEY" ->
                case fromASN1 content of
                    Left err    -> error ("not a valid RSA key: " ++ err)
                    Right (k,_) -> putStrLn "RSA KEY" >> putStrLn (showRSAKey k)
            "DSA PRIVATE KEY" ->
                case fromASN1 content of
                    Left err    -> error ("not a valid DSA key: " ++ err)
                    Right (k,_) -> putStrLn "DSA KEY" >> putStrLn (showDSAKey k)
            _                 ->
                putStrLn ("unknown private key: " ++ show (pemName pem))

optionsCert =
    [ Option []     ["hash"] (NoArg ShowHash) "output certificate hash"
    ]

certMain = getoptMain optionsCert $ \o n ->
    doCertMain o n
crlMain = getoptMain [] $ \o n -> doCRLMain o n
keyMain = getoptMain [] $ \o n -> doKeyMain n
asn1Main = getoptMain [] $ \o n -> doASN1Main n

getoptMain opts f as =
    case getOpt Permute opts as of
        (o,n,[])  -> f o n
        (_,_,err) -> error (show err)

usage = do
    putStrLn "usage: x509-util <cmd>"
    putStrLn "  key : process public key"
    putStrLn "  cert: process X509 certificate"
    putStrLn "  crl : process CRL certificate"
    putStrLn "  asn1: show file asn1"

main = do
    args <- getArgs
    case args of
        []        -> usage
        "x509":as -> certMain as
        "cert":as -> certMain as
        "key":as  -> keyMain as
        "crl":as  -> crlMain as
        "asn1":as -> asn1Main as
        _         -> usage
