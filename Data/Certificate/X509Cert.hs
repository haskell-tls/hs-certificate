module Data.Certificate.X509Cert
	( 
	-- * Data Structure
	  SignatureALG(..)
	, PubKeyALG(..)
	, PubKeyDesc(..)
	, PubKey(..)
	, ASN1StringType(..)
	, ASN1String
	, Certificate(..)
	, CertificateExts(..)

	-- various OID
	, oidCommonName
	, oidCountry
	, oidOrganization
	, oidOrganizationUnit

	-- signature to/from oid
	, oidSig
	, sigOID

	-- * certificate to/from asn1
	, parseCertificate
	, encodeCertificateHeader
	) where

import Data.Word
import Data.List (find)
import Data.ASN1.DER
import Data.Maybe
import Data.ByteString.Lazy (ByteString)
import Data.Text.Lazy (Text)
import qualified Data.ByteString.Lazy as L
import Control.Monad.State
import Control.Monad.Error
import Data.Certificate.X509Internal

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
	| PubKeyALG_DH
	| PubKeyALG_Unknown OID
	deriving (Show,Eq)

data PubKeyDesc =
	  PubKeyRSA (Int, Integer, Integer)              -- ^ RSA format with (len modulus, modulus, e)
	| PubKeyDSA (Integer, Integer, Integer, Integer) -- ^ DSA format with (pub, p, q, g)
	| PubKeyDH (Integer, Integer,Integer, Maybe Integer, ([Word8], Integer))
	                                                 -- ^ DH format with (p,g,q,j,(seed,pgenCounter))
	| PubKeyECDSA [ASN1]                             -- ^ ECDSA format not done yet FIXME
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

data ASN1StringType = UTF8 | Printable | Univ | BMP | IA5 | T61 deriving (Show,Eq)
type ASN1String = (ASN1StringType, Text)

data Certificate = Certificate
	{ certVersion      :: Int                   -- ^ Certificate Version
	, certSerial       :: Integer               -- ^ Certificate Serial number
	, certSignatureAlg :: SignatureALG          -- ^ Certificate Signature algorithm
	, certIssuerDN     :: [ (OID, ASN1String) ] -- ^ Certificate Issuer DN
	, certSubjectDN    :: [ (OID, ASN1String) ] -- ^ Certificate Subject DN
	, certValidity     :: (Time, Time)          -- ^ Certificate Validity period
	, certPubKey       :: PubKey                -- ^ Certificate Public key
	, certExtensions   :: Maybe CertificateExts -- ^ Certificate Extensions
	} deriving (Show,Eq)

data CertificateExts = CertificateExts
	{ certExtKeyUsage             :: Maybe (Bool, [CertKeyUsage])
	, certExtBasicConstraints     :: Maybe (Bool, Bool)
	, certExtSubjectKeyIdentifier :: Maybe (Bool, [Word8])
	, certExtPolicies             :: Maybe (Bool)
	, certExtOthers               :: [ (OID, Bool, [ASN1]) ]
	} deriving (Show,Eq)

oidCommonName, oidCountry, oidOrganization, oidOrganizationUnit :: OID
oidCommonName       = [2,5,4,3]
oidCountry          = [2,5,4,6]
oidOrganization     = [2,5,4,10]
oidOrganizationUnit = [2,5,4,11]

{- | parse a RSA pubkeys from ASN1 encoded bits.
 - return PubKeyRSA (len-modulus, modulus, e) if successful -}
parse_RSA :: ByteString -> PubKeyDesc
parse_RSA bits =
	case decodeASN1Stream $ bits of
		Right [Start Sequence, IntVal modulus, IntVal pubexp, End Sequence] ->
			PubKeyRSA (calculate_modulus modulus 1, modulus, pubexp)
		_ ->
			PubKeyUnknown $ L.unpack bits
	where
		calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)

parse_ECDSA :: ByteString -> PubKeyDesc
parse_ECDSA bits =
	case decodeASN1Stream bits of
		Right l -> PubKeyECDSA l
		Left x  -> PubKeyUnknown $ map (fromIntegral . fromEnum) $ show x
parseCertHeaderVersion :: ParseASN1 Int
parseCertHeaderVersion = do
	v <- onNextContainerMaybe (Container Context 0) $ do
		n <- getNext
		case n of
			IntVal v -> return $ fromIntegral v
			_        -> throwError "unexpected type for version"
	return $ maybe 1 id v

parseCertHeaderSerial :: ParseASN1 Integer
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
	, ([1,2,840,10046,2,1],    PubKeyALG_DH)
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

parseCertHeaderAlgorithmID :: ParseASN1 SignatureALG
parseCertHeaderAlgorithmID = do
	n <- getNextContainer Sequence
	case n of
		[ OID oid, Null ] -> return $ oidSig oid
		[ OID oid ]       -> return $ oidSig oid
		_                 -> throwError ("algorithm ID bad format " ++ show n)

asn1String :: ASN1 -> ASN1String
asn1String (PrintableString x) = (Printable, x)
asn1String (UTF8String x)      = (UTF8, x)
asn1String (UniversalString x) = (Univ, x)
asn1String (BMPString x)       = (BMP, x)
asn1String (IA5String x)       = (IA5, x)
asn1String (T61String x)       = (IA5, x)
asn1String x                   = error ("not a print string " ++ show x)

encodeAsn1String :: ASN1String -> ASN1
encodeAsn1String (Printable, x) = PrintableString x
encodeAsn1String (UTF8, x)      = UTF8String x
encodeAsn1String (Univ, x)      = UniversalString x
encodeAsn1String (BMP, x)       = BMPString x
encodeAsn1String (IA5, x)       = IA5String x
encodeAsn1String (T61, x)       = T61String x

parseCertHeaderDN :: ParseASN1 [ (OID, ASN1String) ]
parseCertHeaderDN = do
	onNextContainer Sequence getDNs
	where
		getDNs = do
			n <- hasNext
			if n
				then do
					dn <- parseDNOne
					liftM (dn :) getDNs
				else return []
		parseDNOne = onNextContainer Set $ do
			s <- getNextContainer Sequence
			case s of
				[OID oid, val] -> return (oid, asn1String val)
				_              -> throwError "expecting sequence"

parseCertHeaderValidity :: ParseASN1 (Time, Time)
parseCertHeaderValidity = do
	n <- getNextContainer Sequence
	case n of
		[ UTCTime t1, UTCTime t2 ] -> return (t1, t2)
		_                          -> throwError "bad validity format"

parseCertHeaderSubjectPK :: ParseASN1 PubKey
parseCertHeaderSubjectPK = onNextContainer Sequence $ do
	l <- getNextContainer Sequence
	bits <- getNextBitString
	case l of
		[OID pkalg,Null]                                                   -> do
			let sig = oidPubKey pkalg
			let desc = case sig of
				PubKeyALG_RSA -> parse_RSA bits
				_             -> PubKeyUnknown $ L.unpack bits
			return $ PubKey sig desc
		[OID pkalg,OID pkalg2]                                            -> do
			let sig = oidPubKey pkalg
			let desc = case sig of
				PubKeyALG_ECDSA  -> parse_ECDSA bits
				_                -> PubKeyUnknown $ L.unpack bits
			return $ PubKey sig desc
		[OID pkalg,Start Sequence,IntVal p,IntVal q,IntVal g,End Sequence] -> do
			let sig = oidPubKey pkalg
			case decodeASN1Stream bits of
				Right [IntVal dsapub] -> return $ PubKey sig (PubKeyDSA (dsapub, p, q, g))
				_                     -> throwError "unrecognized DSA pub format"
		n ->
			throwError ("subject public key bad format : " ++ show n)

	where getNextBitString = getNext >>= \bs -> case bs of
		BitString _ bits -> return bits
		_                -> throwError "expecting bitstring"

-- RFC 5280
parseCertExtensionHelper :: [[ASN1]] -> State CertificateExts ()
parseCertExtensionHelper l = do
	forM_ (mapMaybe extractStruct l) $ \e -> case e of
		([2,5,29,14], critical, Right [OctetString x]) ->
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
		([2,5,29,19], critical, Right [Start Sequence, Boolean True, End Sequence]) ->
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
		extractStruct [OID oid,Boolean True,OctetString obj] = Just (oid, True, decodeASN1Stream obj)
		extractStruct [OID oid,OctetString obj]              = Just (oid, False, decodeASN1Stream obj)
		extractStruct _                                      = Nothing

parseCertExtensions :: ParseASN1 (Maybe CertificateExts)
parseCertExtensions = do
	onNextContainerMaybe (Container Context 3) $ do
		let def = CertificateExts
			{ certExtKeyUsage             = Nothing
			, certExtBasicConstraints     = Nothing
			, certExtSubjectKeyIdentifier = Nothing
			, certExtPolicies             = Nothing
			, certExtOthers               = []
			}
		l <- getNextContainer Sequence
		return $ execState (parseCertExtensionHelper $ makeASN1Sequence l) def

{- | parse header structure of a x509 certificate. the structure the following:
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
-}
parseCertificate :: ParseASN1 Certificate
parseCertificate = do
	version  <- parseCertHeaderVersion
	serial   <- parseCertHeaderSerial
	sigalg   <- parseCertHeaderAlgorithmID
	issuer   <- parseCertHeaderDN
	validity <- parseCertHeaderValidity
	subject  <- parseCertHeaderDN
	pk       <- parseCertHeaderSubjectPK
	exts     <- parseCertExtensions
	hnext    <- hasNext
	when hnext $ throwError "expecting End Of Data."
	
	return $ Certificate
		{ certVersion      = version
		, certSerial       = serial
		, certSignatureAlg = sigalg
		, certIssuerDN     = issuer
		, certSubjectDN    = subject
		, certValidity     = validity
		, certPubKey       = pk
		, certExtensions   = exts
		}

encodeDN :: [ (OID, ASN1String) ] -> [ASN1]
encodeDN dn = asn1Container Sequence $ concatMap dnSet dn
	where
		dnSet (oid, stringy) = asn1Container Set (asn1Container Sequence [OID oid, encodeAsn1String stringy])

encodePK :: PubKey -> [ASN1]
encodePK (PubKey sig (PubKeyRSA (_, modulus, e))) =
	asn1Container Sequence (asn1Container Sequence [ OID $ pubkeyalgOID sig, Null ] ++ [BitString 0 bits])
	where
		(Right bits) = encodeASN1Stream $ asn1Container Sequence [IntVal modulus, IntVal e]

encodePK (PubKey sig (PubKeyDSA (pub, p, q, g)))  =
	asn1Container Sequence (asn1Container Sequence ([OID $ pubkeyalgOID sig] ++ dsaseq) ++ [BitString 0 bits])
	where
		dsaseq       = asn1Container Sequence [IntVal p,IntVal q,IntVal g]
		(Right bits) = encodeASN1Stream [IntVal pub]

encodePK (PubKey sig (PubKeyUnknown l))           = 
	asn1Container Sequence (asn1Container Sequence [OID $ pubkeyalgOID sig, Null] ++ [BitString 0 $ L.pack l])

encodeCertificateHeader :: Certificate -> [ASN1]
encodeCertificateHeader cert =
	eVer ++ eSerial ++ eAlgId ++ eIssuer ++ eValidity ++ eSubject ++ epkinfo ++ eexts
	where
		eVer      = asn1Container (Container Context 0) [IntVal (fromIntegral $ certVersion cert)]
		eSerial   = [IntVal $ certSerial cert]
		eAlgId    = asn1Container Sequence [OID (sigOID $ certSignatureAlg cert), Null]
		eIssuer   = encodeDN $ certIssuerDN cert
		(t1, t2)  = certValidity cert
		eValidity = asn1Container Sequence [UTCTime t1, UTCTime t2]
		eSubject  = encodeDN $ certSubjectDN cert
		epkinfo   = encodePK $ certPubKey cert
		eexts     = [] -- FIXME encode extensions
