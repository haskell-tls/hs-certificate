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
	| SignatureALG_rsa
	| SignatureALG_dsa
	| SignatureALG_dsaWithSHA1
	| SignatureALG_Unknown OID
	deriving (Show, Eq)

data PubKeyDesc =
	  PubKeyRSA (Int, Integer, Integer)              -- ^ RSA format with (len modulus, modulus, e)
	| PubKeyDSA (Integer, Integer, Integer, Integer) -- ^ DSA format with (pub, p, q, g)
	| PubKeyUnknown [Word8]                          -- ^ unrecognized format
	deriving (Show,Eq)

data PubKey = PubKey SignatureALG PubKeyDesc -- OID RSA|DSA|rawdata
	deriving (Show,Eq)

data CertificateDN = CertificateDN
	{ cdnCommonName       :: Maybe String      -- ^ Certificate DN Common Name
	, cdnCountry          :: Maybe String      -- ^ Certificate DN Country of Issuance
	, cdnOrganization     :: Maybe String      -- ^ Certificate DN Organization
	, cdnOrganizationUnit :: Maybe String      -- ^ Certificate DN Organization Unit
	, cdnOthers           :: [ (OID, String) ] -- ^ Certificate DN Other Attributes
	} deriving (Show,Eq)

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
	, certExtOthers               :: [ (OID, Bool, ASN1) ]
	} deriving (Show,Eq)

data Certificate = Certificate
	{ certVersion      :: Int                           -- ^ Certificate Version
	, certSerial       :: Integer                       -- ^ Certificate Serial number
	, certSignatureAlg :: SignatureALG                  -- ^ Certificate Signature algorithm
	, certIssuerDN     :: CertificateDN                 -- ^ Certificate Issuer DN
	, certSubjectDN    :: CertificateDN                 -- ^ Certificate Subject DN
	, certValidity     :: (Time, Time)                  -- ^ Certificate Validity period
	, certPubKey       :: PubKey                        -- ^ Certificate Public key
	, certExtensions   :: Maybe CertificateExts         -- ^ Certificate Extensions
	, certSignature    :: Maybe (SignatureALG, [Word8]) -- ^ Certificate Signature Algorithm and Signature
	, certOthers       :: [ASN1]                        -- ^ any others fields not parsed
	} deriving (Show,Eq)

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
		Other Context 0 (Right [ IntVal v ]) -> getNext >> return (fromIntegral v)
		_                                    -> return 1
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
	, ([1,2,840,113549,1,1,1], SignatureALG_rsa)
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
		Sequence [ OID oid ]       -> return $ oidSig oid
		_                          -> throwError ("algorithm ID bad format " ++ show n)

stringOfASN1String :: ASN1 -> String
stringOfASN1String (PrintableString x) = map (toEnum.fromEnum) $ L.unpack x
stringOfASN1String (UTF8String x)      = map (toEnum.fromEnum) $ L.unpack x
stringOfASN1String (T61String x)       = map (toEnum.fromEnum) $ L.unpack x
stringOfASN1String (UniversalString x) = map (toEnum.fromEnum) $ L.unpack x
stringOfASN1String (BMPString x)       = map (toEnum.fromEnum) $ L.unpack x
stringOfASN1String x                   = error ("not a print string " ++ show x)

parseCertHeaderDNHelper :: [ASN1] -> State CertificateDN ()
parseCertHeaderDNHelper l = do
	forM_ l $ (\e -> case e of
		Set [ Sequence [ OID [2,5,4,3], val ] ] ->
			modify (\s -> s { cdnCommonName = Just $ stringOfASN1String val })
		Set [ Sequence [ OID [2,5,4,6], val ] ] ->
			modify (\s -> s { cdnCountry = Just $ stringOfASN1String val })
		Set [ Sequence [ OID [2,5,4,10], val ] ] ->
			modify (\s -> s { cdnOrganization = Just $ stringOfASN1String val })
		Set [ Sequence [ OID [2,5,4,11], val ] ] ->
			modify (\s -> s { cdnOrganizationUnit = Just $ stringOfASN1String val })
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
			let defdn = CertificateDN
				{ cdnCommonName       = Nothing
				, cdnCountry          = Nothing
				, cdnOrganization     = Nothing
				, cdnOrganizationUnit = Nothing
				, cdnOthers           = []
				}
			return $ execState (parseCertHeaderDNHelper l) defdn 
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
				SignatureALG_rsa                   -> parse_RSA bits
				_                                  -> PubKeyUnknown $ L.unpack bits
			return $ PubKey sig desc
		Sequence [ Sequence [ OID pkalg, Sequence [ IntVal dsaP, IntVal dsaQ, IntVal dsaG ]], BitString _ dsapubenc ] ->
			let sig = oidSig pkalg in
			case decodeASN1 dsapubenc of
				Right (IntVal dsapub) -> return $ PubKey sig (PubKeyDSA (dsapub, dsaP, dsaQ, dsaG))
				_                     -> throwError "unrecognized DSA pub format"
		_ ->
			throwError ("subject public key bad format : " ++ show n)

-- RFC 5280
parseCertExtensionHelper :: [ASN1] -> State CertificateExts ()
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
				Other Context 3 (Right [Sequence l]) -> do
					_ <- getNext
					let def = CertificateExts
						{ certExtKeyUsage             = Nothing
						, certExtBasicConstraints     = Nothing
						, certExtSubjectKeyIdentifier = Nothing
						, certExtPolicies             = Nothing
						, certExtOthers               = []
						}
					return $ Just $ execState (parseCertExtensionHelper l) def
				Other Context 3 _                    ->
					throwError "certificate header bad format"
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

{- | parse root structure of a x509 certificate. this has to be a sequence of 3 objects :
 - * the header
 - * the signature algorithm
 - * the signature -}
processCertificate :: ASN1 -> Either String Certificate
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

encodePK (PubKey sig (PubKeyDSA (pub, p, q, g)))  = Sequence [ Sequence [ OID $ sigOID sig, dsaseq ], BitString 0 bits ]
	where
		dsaseq = Sequence [ IntVal p, IntVal q, IntVal g ]
		bits   = encodeASN1 $ IntVal pub

encodePK (PubKey sig (PubKeyUnknown l))           = Sequence [ Sequence [ OID $ sigOID sig, Null ], BitString 0 (L.pack l) ]

encodeCertificateHeader :: Certificate -> [ASN1]
encodeCertificateHeader cert =
	[ eVer, eSerial, eAlgId, eIssuer, eValidity, eSubject, epkinfo ] ++ others
	where
		eVer      = Other Context 0 (Right [ IntVal (fromIntegral $ certVersion cert) ])
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
