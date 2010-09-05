{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Data.Certificate.X509
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Read/Write X509 certificate
--

module Data.Certificate.X509 (
	-- * Data Structure
	PubKeyDesc(..),
	PubKey(..),
	CertificateDN(..),
	Certificate(..),

	-- * serialization from ASN1 bytestring
	decodeCertificate,
	encodeCertificate
	) where

import Data.Word
import Data.List (find)
import Data.ASN1.DER
import Data.Maybe
import qualified Data.ByteString.Lazy as L
import Control.Monad.State
import Control.Monad.Error

{-
the structure of an X509 Certificate is the following:

Certificate
	Version
	Serial Number
	Algorithm ID
	Issuer
	Validity
		Not Before
		Not After
	Subject
	Subject Public Key Info
		Public Key Algorithm
		Subject Public Key
	Issuer Unique Identifier (Optional)  (>= 2)
	Subject Unique Identifier (Optional) (>= 2)
	Extensions (Optional)   (>= v3)
	...
Certificate Signature Algorithm
Certificate Signature
-}

{-
data CertError =
	  CertErrorMissing String
	| CertErrorBadFormat String
	| CertErrorMisc String
	deriving (Show)
-}
type OID = [Integer]

data SignatureALG =
	  SignatureALG_md5WithRSAEncryption
	| SignatureALG_md2WithRSAEncryption
	| SignatureALG_sha1WithRSAEncryption
	| SignatureALG_dsa
	| SignatureALG_dsaWithSHA1
	| SignatureALG_Unknown OID
	deriving (Show, Eq)

data PubKeyDesc =
	  PubKeyRSA (Int, Integer, Integer) -- len modulus, modulus, e
	| PubKeyDSA (L.ByteString, Integer, Integer, Integer) -- pub, p, q, g
	| PubKeyUnknown [Word8]
	deriving (Show)

data PubKey = PubKey SignatureALG PubKeyDesc -- OID RSA|DSA|rawdata
	deriving (Show)

data CertificateDN = CertificateDN {
	cdnCommonName       :: Maybe String,
	cdnCountry          :: Maybe String,
	cdnOrganization     :: Maybe String,
	cdnOrganizationUnit :: Maybe String,
	cdnOthers           :: [ (OID, String) ]
	} deriving (Show)

-- FIXME use a proper standard type for representing time.
type Time = (Int, Int, Int, Int, Int, Int, Bool)

data Certificate = Certificate {
	certVersion      :: Int,
	certSerial       :: Integer,
	certSignatureAlg :: SignatureALG,
	certIssuerDN     :: CertificateDN,
	certSubjectDN    :: CertificateDN,
	certValidity     :: (Time, Time),
	certPubKey       :: PubKey,
	certExtensions   :: Maybe [ASN1],
	certSignature    :: Maybe (SignatureALG, [Word8]),
	certOthers       :: [ASN1]
	} deriving (Show)

{- | parse a RSA pubkeys from ASN1 encoded bits.
 - return PubKeyRSA (len-modulus, modulus, e) if successful -}
parse_RSA :: L.ByteString -> PubKeyDesc
parse_RSA bits =
	case decodeASN1 $ bits of
		Right (Sequence [ IntVal modulus, IntVal pubexp ]) ->
			PubKeyRSA (calculate_modulus modulus 1, modulus, pubexp)
		_ ->
			PubKeyUnknown $ L.unpack bits
	where
		calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)

newtype ParseCert a = P { runP :: ErrorT String (State [ASN1]) a }
	deriving (Monad, MonadError String)

runParseCert :: ParseCert a -> [ASN1] -> Either String a
runParseCert f s =
	case runState (runErrorT (runP f)) s of
		(Left err, _) -> Left err
		(Right r, _) -> Right r

getNext :: ParseCert ASN1
getNext = do
	list <- P (lift get)
	case list of
		[]    -> throwError "empty"
		(h:l) -> P (lift (put l)) >> return h

getRemaining :: ParseCert [ASN1]
getRemaining = P (lift get)

hasNext :: ParseCert Bool
hasNext = do
	list <- P (lift get)
	case list of
		[] -> return False
		_  -> return True

lookNext :: ParseCert ASN1
lookNext = do
	list <- P (lift get)
	case list of
		[]    -> throwError "empty"
		(h:_) -> return h

parseCertHeaderVersion :: ParseCert Int
parseCertHeaderVersion = do
	n <- lookNext
	v <- case n of
		Other Application 0 (Right [ IntVal v ]) -> getNext >> return (fromIntegral v)
		_                                        -> return 1
	return v

parseCertHeaderSerial :: ParseCert Integer
parseCertHeaderSerial = do
	n <- getNext
	case n of
		IntVal v -> return v
		_        -> throwError ("missing serial" ++ show n)

sig_table :: [ (OID, SignatureALG) ]
sig_table =
	[ ([1,2,840,113549,1,1,5], SignatureALG_sha1WithRSAEncryption)
	, ([1,2,840,113549,1,1,4], SignatureALG_md5WithRSAEncryption)
	, ([1,2,840,113549,1,1,2], SignatureALG_md2WithRSAEncryption)
	, ([1,2,840,10040,4,1],    SignatureALG_dsa)
	, ([1,2,840,10040,4,3],    SignatureALG_dsaWithSHA1)
	]


oidSig :: OID -> SignatureALG
oidSig oid = maybe (SignatureALG_Unknown oid) snd $ find ((==) oid . fst) sig_table

sigOID :: SignatureALG -> OID
sigOID (SignatureALG_Unknown oid) = oid
sigOID sig = maybe [] fst $ find ((==) sig . snd) sig_table

parseCertHeaderAlgorithmID :: ParseCert SignatureALG
parseCertHeaderAlgorithmID = do
	n <- getNext
	case n of
		Sequence [ OID oid, Null ] -> return $ oidSig oid
		_                          -> throwError "algorithm ID bad format"

stringOfASN1PrintString :: ASN1 -> String
stringOfASN1PrintString (PrintableString x) = map (toEnum.fromEnum) $ L.unpack x
stringOfASN1PrintString (UTF8String x)      = map (toEnum.fromEnum) $ L.unpack x
stringOfASN1PrintString x                   = error ("not a print string " ++ show x)

parseCertHeaderDNHelper :: [ASN1] -> State CertificateDN ()
parseCertHeaderDNHelper l = do
	forM_ l $ (\e -> do
		case e of
			Set [ Sequence [ OID [2,5,4,3], val ] ] ->
				modify (\s -> s { cdnCommonName = Just $ stringOfASN1PrintString val })
			Set [ Sequence [ OID [2,5,4,6], val ] ] ->
				modify (\s -> s { cdnCountry = Just $ stringOfASN1PrintString val })
			Set [ Sequence [ OID [2,5,4,10], val ] ] ->
				modify (\s -> s { cdnOrganization = Just $ stringOfASN1PrintString val })
			Set [ Sequence [ OID [2,5,4,11], val ] ] ->
				modify (\s -> s { cdnOrganizationUnit = Just $ stringOfASN1PrintString val })
			Set [ Sequence [ OID oid, val ] ] ->
				modify (\s -> s { cdnOthers = (oid, show val) : cdnOthers s })
			_      ->
				return ()
		)

parseCertHeaderDN :: ParseCert CertificateDN
parseCertHeaderDN = do
	n <- getNext
	case n of
		Sequence l -> do
			let defdn = CertificateDN {
				cdnCommonName       = Nothing,
				cdnCountry          = Nothing,
				cdnOrganization     = Nothing,
				cdnOrganizationUnit = Nothing,
				cdnOthers           = []
				}
			let dn = execState (parseCertHeaderDNHelper l) defdn 
			return dn
		_          -> throwError "Distinguished name bad format"

parseCertHeaderValidity :: ParseCert (Time, Time)
parseCertHeaderValidity = do
	n <- getNext
	case n of
		Sequence [ UTCTime t1, UTCTime t2 ] -> return (t1, t2)
		_                                   -> throwError "bad validity format"

parseCertHeaderSubjectPK :: ParseCert PubKey
parseCertHeaderSubjectPK = do
	n <- getNext
	case n of
		Sequence [ Sequence [ OID pkalg, Null], BitString _ bits ] -> do
			let sig = oidSig pkalg
			let desc = case sig of
				SignatureALG_sha1WithRSAEncryption -> parse_RSA bits
				SignatureALG_md5WithRSAEncryption  -> parse_RSA bits
				SignatureALG_md2WithRSAEncryption  -> parse_RSA bits
				_                                  -> PubKeyUnknown $ L.unpack bits
			return $ PubKey sig desc
		Sequence [ Sequence [ OID pkalg, Sequence [ IntVal dsaP, IntVal dsaQ, IntVal dsaG ]], BitString _ dsapub ] ->
			let sig = oidSig pkalg in
			return $ PubKey sig (PubKeyDSA (dsapub, dsaP, dsaQ, dsaG))
		_ ->
			throwError ("subject public key bad format : " ++ show n)

parseCertExtensions :: ParseCert (Maybe [ASN1])
parseCertExtensions = do
	h <- hasNext
	if h
		then do
			n <- lookNext
			case n of
				Other Application 3 (Right l) -> getNext >> return (Just l)
				_                             -> return Nothing
		else return Nothing

{- | parse header structure of a x509 certificate. it contains
 - the version, the serial number, the issuer DN, the validity period,
 - the subject DN, and the public keys -}
parseCertificate :: ParseCert Certificate
parseCertificate = do
	version  <- parseCertHeaderVersion
	serial   <- parseCertHeaderSerial
	sigalg   <- parseCertHeaderAlgorithmID
	issuer   <- parseCertHeaderDN
	validity <- parseCertHeaderValidity
	subject  <- parseCertHeaderDN
	pk       <- parseCertHeaderSubjectPK
	exts     <- parseCertExtensions
	l        <- getRemaining
	
	return $ Certificate {
		certVersion      = version,
		certSerial       = serial,
		certSignatureAlg = sigalg,
		certIssuerDN     = issuer,
		certSubjectDN    = subject,
		certValidity     = validity,
		certPubKey       = pk,
		certSignature    = Nothing,
		certExtensions   = exts,
		certOthers       = l
		}

processCertificate :: ASN1 -> ASN1 -> ASN1 -> Either String Certificate
processCertificate header sigalg sig = do
	let sigAlg =
		case sigalg of
			Sequence [ OID oid, Null ] -> oidSig oid
			_                          -> SignatureALG_Unknown []
	let sigbits =
		case sig of
			BitString _ bits -> bits
			_                -> error "signature not in right format"
	case header of
		Sequence l ->
			let cert = runParseCert parseCertificate l in
			either Left (\c -> Right $ c { certSignature = Just (sigAlg, L.unpack sigbits) }) cert
		_          -> Left "Certificate is not a sequence" 
	

{- | parse root structure of a x509 certificate. this has to be a sequence of 3 objects :
 - * the header
 - * the signature algorithm
 - * the signature -}
parseCertRoot :: ASN1 -> Either String Certificate
parseCertRoot (Sequence [ header, sigalg, sig ]) = processCertificate header sigalg sig
parseCertRoot x = Left ("certificate root element error: " ++ show x)

decodeCertificate :: L.ByteString -> Either String Certificate
decodeCertificate by = either (Left . show) parseCertRoot $ decodeASN1 by

encodeDN :: CertificateDN -> ASN1
encodeDN dn = Sequence sets
	where
		sets = catMaybes [
			maybe Nothing (mapSet [2,5,4,3]) $ cdnCommonName dn,
			maybe Nothing (mapSet [2,5,4,6]) $ cdnCountry dn,
			maybe Nothing (mapSet [2,5,4,10]) $ cdnOrganization dn,
			maybe Nothing (mapSet [2,5,4,11]) $ cdnOrganizationUnit dn
			] 
		mapSet oid str = Just $ Set [
			Sequence [
				OID oid,
				PrintableString (L.pack $ map (toEnum . fromEnum) str) ]
			]

encodePK :: PubKey -> ASN1
encodePK (PubKey sig (PubKeyRSA (_, modulus, e))) = Sequence [ Sequence [ OID $ sigOID sig, Null ], BitString 0 bits ]
	where bits = encodeASN1 $ Sequence [ IntVal modulus, IntVal e ]

encodePK (PubKey sig (PubKeyDSA (bits, p, q, g))) = Sequence [ Sequence [ OID $ sigOID sig, dsaseq ], BitString 0 bits ]
	where dsaseq = Sequence [ IntVal p, IntVal q, IntVal g ]

encodePK (PubKey sig (PubKeyUnknown l))           = Sequence [ Sequence [ OID $ sigOID sig, Null ], BitString 0 (L.pack l) ]

encodeCertificateHeader :: Certificate -> [ASN1]
encodeCertificateHeader cert =
	[ eVer, eSerial, eAlgId, eIssuer, eValidity, eSubject, epkinfo ] ++ others
	where
		eVer      = Other Application 0 (Right [ IntVal (fromIntegral $ certVersion cert) ])
		eSerial   = IntVal $ certSerial cert
		eAlgId    = Sequence [ OID (sigOID $ certSignatureAlg cert), Null ]
		eIssuer   = encodeDN $ certIssuerDN cert
		(t1, t2)  = certValidity cert
		eValidity = Sequence [ UTCTime t1, UTCTime t2 ]
		eSubject  = encodeDN $ certSubjectDN cert
		epkinfo   = encodePK $ certPubKey cert
		others    = []

encodeCertificate :: Certificate -> L.ByteString
encodeCertificate cert = encodeASN1 rootSeq
	where
		sigalg = Sequence []
		sig = Sequence []
		header = Sequence $ encodeCertificateHeader cert
		rootSeq = Sequence [ header, sigalg, sig ]
