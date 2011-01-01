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

module Data.Certificate.X509
	(
	-- * Data Structure
	  SignatureALG(..)
	, PubKeyALG(..)
	, PubKeyDesc(..)
	, PubKey(..)
	, Certificate(..)
	, ASN1StringType(..)
	, ASN1String

	-- * some common OIDs found in certificate Distinguish Names
	, oidCommonName
	, oidCountry
	, oidOrganization
	, oidOrganizationUnit

	-- * serialization from ASN1 bytestring
	, decodeCertificate
	, encodeCertificate
	) where

import Data.Word
import Data.List (find)
import Data.ASN1.DER hiding (ASN1(..))
import Data.ASN1.Types (ASN1t(..))
import Data.Maybe
import Data.ByteString.Lazy (ByteString)
import Data.Text.Lazy (Text)
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
	| SignatureALG_dsaWithSHA1
	| SignatureALG_ecdsaWithSHA384
	| SignatureALG_Unknown OID
	deriving (Show, Eq)

data PubKeyALG =
	  PubKeyALG_RSA
	| PubKeyALG_DSA
	| PubKeyALG_ECDSA
	| PubKeyALG_Unknown OID
	deriving (Show,Eq)

data PubKeyDesc =
	  PubKeyRSA (Int, Integer, Integer)              -- ^ RSA format with (len modulus, modulus, e)
	| PubKeyDSA (Integer, Integer, Integer, Integer) -- ^ DSA format with (pub, p, q, g)
	| PubKeyECDSA ASN1t                              -- ^ ECDSA format not done yet FIXME
	| PubKeyUnknown [Word8]                          -- ^ unrecognized format
	deriving (Show,Eq)

data PubKey = PubKey PubKeyALG PubKeyDesc -- OID RSA|DSA|rawdata
	deriving (Show,Eq)

-- FIXME use a proper standard type for representing time.
type Time = (Int, Int, Int, Int, Int, Int, Bool)

data CertKeyUsage =
	  CertKeyUsageDigitalSignature
	| CertKeyUsageNonRepudiation
	| CertKeyUsageKeyEncipherment
	| CertKeyUsageDataEncipherment
	| CertKeyUsageKeyAgreement
	| CertKeyUsageKeyCertSign
	| CertKeyUsageCRLSign
	| CertKeyUsageEncipherOnly
	| CertKeyUsageDecipherOnly
	deriving (Show, Eq)

data CertificateExts = CertificateExts
	{ certExtKeyUsage             :: Maybe (Bool, [CertKeyUsage])
	, certExtBasicConstraints     :: Maybe (Bool, Bool)
	, certExtSubjectKeyIdentifier :: Maybe (Bool, [Word8])
	, certExtPolicies             :: Maybe (Bool)
	, certExtOthers               :: [ (OID, Bool, ASN1t) ]
	} deriving (Show,Eq)

data ASN1StringType = UTF8 | Printable | Univ | BMP | IA5 deriving (Show,Eq)
type ASN1String = (ASN1StringType, Text)

oidCommonName, oidCountry, oidOrganization, oidOrganizationUnit :: OID
oidCommonName       = [2,5,4,3]
oidCountry          = [2,5,4,6]
oidOrganization     = [2,5,4,10]
oidOrganizationUnit = [2,5,4,11]

data Certificate = Certificate
	{ certVersion      :: Int                           -- ^ Certificate Version
	, certSerial       :: Integer                       -- ^ Certificate Serial number
	, certSignatureAlg :: SignatureALG                  -- ^ Certificate Signature algorithm
	, certIssuerDN     :: [ (OID, ASN1String) ]         -- ^ Certificate Issuer DN
	, certSubjectDN    :: [ (OID, ASN1String) ]         -- ^ Certificate Subject DN
	, certValidity     :: (Time, Time)                  -- ^ Certificate Validity period
	, certPubKey       :: PubKey                        -- ^ Certificate Public key
	, certExtensions   :: Maybe CertificateExts         -- ^ Certificate Extensions
	, certSignature    :: Maybe (SignatureALG, [Word8]) -- ^ Certificate Signature Algorithm and Signature
	, certOthers       :: [ASN1t]                        -- ^ any others fields not parsed
	} deriving (Show,Eq)

{- | parse a RSA pubkeys from ASN1 encoded bits.
 - return PubKeyRSA (len-modulus, modulus, e) if successful -}
parse_RSA :: ByteString -> PubKeyDesc
parse_RSA bits =
	case decodeASN1 $ bits of
		Right (Sequence [ IntVal modulus, IntVal pubexp ]) ->
			PubKeyRSA (calculate_modulus modulus 1, modulus, pubexp)
		_ ->
			PubKeyUnknown $ L.unpack bits
	where
		calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)

parse_ECDSA :: ByteString -> PubKeyDesc
parse_ECDSA bits =
	case decodeASN1 bits of
		Right l -> PubKeyECDSA l
		Left x  -> PubKeyUnknown $ map (fromIntegral . fromEnum) $ show x

newtype ParseCert a = P { runP :: ErrorT String (State [ASN1t]) a }
	deriving (Monad, MonadError String)

runParseCert :: ParseCert a -> [ASN1t] -> Either String a
runParseCert f s =
	case runState (runErrorT (runP f)) s of
		(Left err, _) -> Left err
		(Right r, _) -> Right r

getNext :: ParseCert ASN1t
getNext = do
	list <- P (lift get)
	case list of
		[]    -> throwError "empty"
		(h:l) -> P (lift (put l)) >> return h

getRemaining :: ParseCert [ASN1t]
getRemaining = P (lift get)

hasNext :: ParseCert Bool
hasNext = do
	list <- P (lift get)
	case list of
		[] -> return False
		_  -> return True

lookNext :: ParseCert ASN1t
lookNext = do
	list <- P (lift get)
	case list of
		[]    -> throwError "empty"
		(h:_) -> return h

parseCertHeaderVersion :: ParseCert Int
parseCertHeaderVersion = do
	n <- lookNext
	v <- case n of
		Container Context 0 [ IntVal v ] -> getNext >> return (fromIntegral v)
		_                                -> return 1
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
	, ([1,2,840,10040,4,3],    SignatureALG_dsaWithSHA1)
	, ([1,2,840,10045,4,3,3],  SignatureALG_ecdsaWithSHA384)
	]

pk_table :: [ (OID, PubKeyALG) ]
pk_table =
	[ ([1,2,840,113549,1,1,1], PubKeyALG_RSA)
	, ([1,2,840,10040,4,1],    PubKeyALG_DSA)
	, ([1,2,840,10045,2,1],    PubKeyALG_ECDSA)
	]

oidSig :: OID -> SignatureALG
oidSig oid = maybe (SignatureALG_Unknown oid) snd $ find ((==) oid . fst) sig_table

oidPubKey :: OID -> PubKeyALG
oidPubKey oid = maybe (PubKeyALG_Unknown oid) snd $ find ((==) oid . fst) pk_table

sigOID :: SignatureALG -> OID
sigOID (SignatureALG_Unknown oid) = oid
sigOID sig = maybe [] fst $ find ((==) sig . snd) sig_table

pubkeyalgOID :: PubKeyALG -> OID
pubkeyalgOID (PubKeyALG_Unknown oid) = oid
pubkeyalgOID sig = maybe [] fst $ find ((==) sig . snd) pk_table

parseCertHeaderAlgorithmID :: ParseCert SignatureALG
parseCertHeaderAlgorithmID = do
	n <- getNext
	case n of
		Sequence [ OID oid, Null ] -> return $ oidSig oid
		Sequence [ OID oid ]       -> return $ oidSig oid
		_                          -> throwError ("algorithm ID bad format " ++ show n)

asn1String :: ASN1t -> ASN1String
asn1String (PrintableString x) = (Printable, x)
asn1String (UTF8String x)      = (UTF8, x)
asn1String (UniversalString x) = (Univ, x)
asn1String (BMPString x)       = (BMP, x)
asn1String (IA5String x)       = (IA5, x)
asn1String x                   = error ("not a print string " ++ show x)

encodeAsn1String :: ASN1String -> ASN1t
encodeAsn1String (Printable, x) = PrintableString x
encodeAsn1String (UTF8, x)      = UTF8String x
encodeAsn1String (Univ, x)      = UniversalString x
encodeAsn1String (BMP, x)       = BMPString x
encodeAsn1String (IA5, x)       = IA5String x

parseCertHeaderDN :: ParseCert [ (OID, ASN1String) ]
parseCertHeaderDN = do
	n <- getNext
	case n of
		Sequence l -> mapM parseDNOne l
		_          -> throwError "Distinguished name bad format"
	where
		parseDNOne (Set [ Sequence [OID oid, val]]) = return (oid, asn1String val)
		parseDNOne _                                = throwError "field in dn bad format"

parseCertHeaderValidity :: ParseCert (Time, Time)
parseCertHeaderValidity = do
	n <- getNext
	case n of
		Sequence [ UTCTime t1, UTCTime t2 ] -> return (t1, t2)
		_                                   -> throwError "bad validity format"

matchPubKey :: ASN1t -> ParseCert PubKey
matchPubKey (Sequence[Sequence[OID pkalg,Null],BitString _ bits]) = do
	let sig = oidPubKey pkalg
	let desc = case sig of
		PubKeyALG_RSA                      -> parse_RSA bits
		_                                  -> PubKeyUnknown $ L.unpack bits
	return $ PubKey sig desc

matchPubKey (Sequence[Sequence[OID pkalg,OID pkgalg2],BitString _ bits]) = do
	let sig = oidPubKey pkalg
	let desc = case sig of
		PubKeyALG_ECDSA  -> parse_ECDSA bits
		_                -> PubKeyUnknown $ L.unpack bits
	return $ PubKey sig desc


matchPubKey (Sequence[Sequence[OID pkalg,Sequence[IntVal p,IntVal q,IntVal g]], BitString _ pubenc ]) = do
	let sig = oidPubKey pkalg
	case decodeASN1 pubenc of
		Right (IntVal dsapub) -> return $ PubKey sig (PubKeyDSA (dsapub, p, q, g))
		_                     -> throwError "unrecognized DSA pub format"


matchPubKey n = throwError ("subject public key bad format : " ++ show n)

parseCertHeaderSubjectPK :: ParseCert PubKey
parseCertHeaderSubjectPK = getNext >>= matchPubKey

-- RFC 5280
parseCertExtensionHelper :: [ASN1t] -> State CertificateExts ()
parseCertExtensionHelper l = do
	forM_ (mapMaybe extractStruct l) $ \e -> case e of
		([2,5,29,14], critical, Right (OctetString x)) ->
			modify (\s -> s { certExtSubjectKeyIdentifier = Just (critical, L.unpack x) })
		{-
		([2,5,29,15], critical, Right (BitString _ _)) ->
			all the flags:
			digitalSignature        (0),
			nonRepudiation          (1), -- recent editions of X.509 have renamed this bit to contentCommitment
			keyEncipherment         (2),
			dataEncipherment        (3),
			keyAgreement            (4),
			keyCertSign             (5),
			cRLSign                 (6),
			encipherOnly            (7),
			decipherOnly            (8) }

			return ()
		-}
		([2,5,29,19], critical, Right (Sequence [Boolean True])) ->
			modify (\s -> s { certExtBasicConstraints = Just (critical, True) })
		{-
		([2,5,29,31], critical, obj) -> -- distributions points
			return ()
		([2,5,29,32], critical, obj) -> -- policies
			return ()
		([2,5,29,33], critical, obj) -> -- policies mapping
			return ()
		([2,5,29,35], critical, obj) -> -- authority key identifer
			return ()
		-}
		(oid, critical, Right obj)    ->
			modify (\s -> s { certExtOthers = (oid, critical, obj) : certExtOthers s })
		(_, True, Left _)             -> fail "critical extension not understood"
		(_, False, Left _)            -> return ()
	where
		extractStruct (Sequence [ OID oid, Boolean True, OctetString obj ]) = Just (oid, True, decodeASN1 obj)
		extractStruct (Sequence [ OID oid, OctetString obj ])               = Just (oid, False, decodeASN1 obj)
		extractStruct _                                                     = Nothing

parseCertExtensions :: ParseCert (Maybe CertificateExts)
parseCertExtensions = do
	h <- hasNext
	if h
		then do
			n <- lookNext
			case n of
				Container Context 3 [Sequence l] -> do
					_ <- getNext
					let def = CertificateExts
						{ certExtKeyUsage             = Nothing
						, certExtBasicConstraints     = Nothing
						, certExtSubjectKeyIdentifier = Nothing
						, certExtPolicies             = Nothing
						, certExtOthers               = []
						}
					return $ Just $ execState (parseCertExtensionHelper l) def
				_                                    ->
					return Nothing
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
	
	return $ Certificate
		{ certVersion      = version
		, certSerial       = serial
		, certSignatureAlg = sigalg
		, certIssuerDN     = issuer
		, certSubjectDN    = subject
		, certValidity     = validity
		, certPubKey       = pk
		, certSignature    = Nothing
		, certExtensions   = exts
		, certOthers       = l
		}

{- | parse root structure of a x509 certificate. this has to be a sequence of 3 objects :
 - * the header
 - * the signature algorithm
 - * the signature -}
processCertificate :: ASN1t -> Either String Certificate
processCertificate (Sequence [ header, sigalg, sig ]) = do
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
	
processCertificate x = Left ("certificate root element error: " ++ show x)

{- | decode a X509 certificate from a bytestring -}
decodeCertificate :: L.ByteString -> Either String Certificate
decodeCertificate by = either (Left . show) processCertificate $ decodeASN1 by

encodeDN :: [ (OID, ASN1String) ] -> ASN1t
encodeDN dn = Sequence $ map dnSet dn
	where
		dnSet (oid, stringy) = Set [ Sequence [ OID oid, encodeAsn1String stringy ]]

encodePK :: PubKey -> ASN1t
encodePK (PubKey sig (PubKeyRSA (_, modulus, e))) = Sequence [ Sequence [ OID $ pubkeyalgOID sig, Null ], BitString 0 bits ]
	where bits = encodeASN1 $ Sequence [ IntVal modulus, IntVal e ]

encodePK (PubKey sig (PubKeyDSA (pub, p, q, g)))  = Sequence [ Sequence [ OID $ pubkeyalgOID sig, dsaseq ], BitString 0 bits ]
	where
		dsaseq = Sequence [ IntVal p, IntVal q, IntVal g ]
		bits   = encodeASN1 $ IntVal pub

encodePK (PubKey sig (PubKeyUnknown l))           = Sequence [ Sequence [ OID $ pubkeyalgOID sig, Null ], BitString 0 (L.pack l) ]

encodeCertificateHeader :: Certificate -> [ASN1t]
encodeCertificateHeader cert =
	[ eVer, eSerial, eAlgId, eIssuer, eValidity, eSubject, epkinfo ] ++ others
	where
		eVer      = Container Context 0 [ IntVal (fromIntegral $ certVersion cert) ]
		eSerial   = IntVal $ certSerial cert
		eAlgId    = Sequence [ OID (sigOID $ certSignatureAlg cert), Null ]
		eIssuer   = encodeDN $ certIssuerDN cert
		(t1, t2)  = certValidity cert
		eValidity = Sequence [ UTCTime t1, UTCTime t2 ]
		eSubject  = encodeDN $ certSubjectDN cert
		epkinfo   = encodePK $ certPubKey cert
		others    = []

{-| encode a X509 certificate to a bytestring -}
encodeCertificate :: Certificate -> L.ByteString
encodeCertificate cert = encodeASN1 rootSeq
	where
		(sigalg, sigbits) = fromJust $ certSignature cert
		esigalg = Sequence [ OID (sigOID sigalg), Null ]
		esig = BitString 0 $ L.pack sigbits
		header = Sequence $ encodeCertificateHeader cert
		rootSeq = Sequence [ header, esigalg, esig ]
