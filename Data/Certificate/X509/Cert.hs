module Data.Certificate.X509.Cert
	( 
	-- * Data Structure
	  SignatureALG(..)
	, HashALG(..)
	, PubKeyALG(..)
	, PubKey(..)
	, ASN1StringType(..)
	, ASN1String
	, Certificate(..)

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

	-- public key parser
	, parse_RSA

	-- * extensions
	, module Data.Certificate.X509.Ext
	) where

import Data.Word
import Data.List (find, sortBy)
import Data.ASN1.DER
import Data.ASN1.BitArray
import Data.Maybe
import Data.Time.Calendar
import Data.Time.Clock (DiffTime, secondsToDiffTime)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as L
import Control.Applicative ((<$>))
import Control.Monad.State
import Control.Monad.Error
import Data.Certificate.X509.Internal
import Data.Certificate.X509.Ext
import qualified Crypto.Types.PubKey.RSA as RSA
import qualified Crypto.Types.PubKey.DSA as DSA

data HashALG =
	  HashMD2
	| HashMD5
	| HashSHA1
	| HashSHA224
	| HashSHA256
	| HashSHA384
	| HashSHA512
	deriving (Show,Eq)

data PubKeyALG =
	  PubKeyALG_RSA
	| PubKeyALG_DSA
	| PubKeyALG_ECDSA
	| PubKeyALG_DH
	| PubKeyALG_Unknown OID
	deriving (Show,Eq)

data SignatureALG =
	  SignatureALG HashALG PubKeyALG
	| SignatureALG_Unknown OID
	deriving (Show,Eq)

data PubKey =
	  PubKeyRSA RSA.PublicKey -- ^ RSA public key
	| PubKeyDSA DSA.PublicKey -- ^ DSA public key
	| PubKeyDH (Integer,Integer,Integer,Maybe Integer,([Word8], Integer))
	                            -- ^ DH format with (p,g,q,j,(seed,pgenCounter))
	| PubKeyECDSA [ASN1]        -- ^ ECDSA format not done yet FIXME
	| PubKeyUnknown OID [Word8] -- ^ unrecognized format
	deriving (Show,Eq)

type Time = (Day, DiffTime, Bool)

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
type ASN1String = (ASN1StringType, String)

data Certificate = Certificate
	{ certVersion      :: Int                    -- ^ Certificate Version
	, certSerial       :: Integer                -- ^ Certificate Serial number
	, certSignatureAlg :: SignatureALG           -- ^ Certificate Signature algorithm
	, certIssuerDN     :: [ (OID, ASN1String) ]  -- ^ Certificate Issuer DN
	, certSubjectDN    :: [ (OID, ASN1String) ]  -- ^ Certificate Subject DN
	, certValidity     :: (Time, Time)           -- ^ Certificate Validity period
	, certPubKey       :: PubKey                 -- ^ Certificate Public key
	, certExtensions   :: Maybe [ExtensionRaw]   -- ^ Certificate Extensions
	} deriving (Show,Eq)

oidCommonName, oidCountry, oidOrganization, oidOrganizationUnit :: OID
oidCommonName       = [2,5,4,3]
oidCountry          = [2,5,4,6]
oidOrganization     = [2,5,4,10]
oidOrganizationUnit = [2,5,4,11]

{- | parse a RSA pubkeys from ASN1 encoded bits.
 - return RSA.PublicKey (len-modulus, modulus, e) if successful -}
parse_RSA :: ByteString -> Either String RSA.PublicKey
parse_RSA bits =
	case decodeASN1Stream $ bits of
		Right [Start Sequence, IntVal modulus, IntVal pubexp, End Sequence] ->
			Right $ RSA.PublicKey
				{ RSA.public_size = calculate_modulus modulus 1
				, RSA.public_n    = modulus
				, RSA.public_e    = pubexp
				}
		_ -> Left "bad RSA format"
	where
		calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)

parse_ECDSA :: ByteString -> ParseASN1 PubKey
parse_ECDSA bits =
	case decodeASN1Stream bits of
		Right l -> return $ PubKeyECDSA l
		Left _  -> return $ PubKeyUnknown (pubkeyalgOID PubKeyALG_ECDSA) (L.unpack bits)

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
	[ ([1,2,840,113549,1,1,5], SignatureALG HashSHA1 PubKeyALG_RSA)
	, ([1,2,840,113549,1,1,4], SignatureALG HashMD5 PubKeyALG_RSA)
	, ([1,2,840,113549,1,1,2], SignatureALG HashMD2 PubKeyALG_RSA)
	, ([1,2,840,113549,1,1,11], SignatureALG HashSHA256 PubKeyALG_RSA)
	, ([1,2,840,113549,1,1,12], SignatureALG HashSHA384 PubKeyALG_RSA)
	, ([1,2,840,10040,4,3],    SignatureALG HashSHA1 PubKeyALG_DSA)
	, ([1,2,840,10045,4,3,1],  SignatureALG HashSHA224 PubKeyALG_ECDSA)
	, ([1,2,840,10045,4,3,2],  SignatureALG HashSHA256 PubKeyALG_ECDSA)
	, ([1,2,840,10045,4,3,3],  SignatureALG HashSHA384 PubKeyALG_ECDSA)
	, ([1,2,840,10045,4,3,4],  SignatureALG HashSHA512 PubKeyALG_ECDSA)
	]

pk_table :: [ (OID, PubKeyALG) ]
pk_table =
	[ ([1,2,840,113549,1,1,1], PubKeyALG_RSA)
	, ([1,2,840,10040,4,1],    PubKeyALG_DSA)
	, ([1,2,840,10045,2,1],    PubKeyALG_ECDSA)
	, ([1,2,840,10046,2,1],    PubKeyALG_DH)
	]

oidSig :: OID -> SignatureALG
oidSig oid = maybe (SignatureALG_Unknown oid) id $ lookup oid sig_table

oidPubKey :: OID -> PubKeyALG
oidPubKey oid = maybe (PubKeyALG_Unknown oid) id $ lookup oid pk_table

sigOID :: SignatureALG -> OID
sigOID (SignatureALG_Unknown oid) = oid
sigOID sig = maybe [] fst $ find ((==) sig . snd) sig_table

pubkeyalgOID :: PubKeyALG -> OID
pubkeyalgOID (PubKeyALG_Unknown oid) = oid
pubkeyalgOID sig = maybe [] fst $ find ((==) sig . snd) pk_table

pubkeyToAlg :: PubKey -> PubKeyALG
pubkeyToAlg (PubKeyRSA _)         = PubKeyALG_RSA
pubkeyToAlg (PubKeyDSA _)         = PubKeyALG_DSA
pubkeyToAlg (PubKeyDH _)          = PubKeyALG_DH
pubkeyToAlg (PubKeyECDSA _)       = PubKeyALG_ECDSA
pubkeyToAlg (PubKeyUnknown oid _) = PubKeyALG_Unknown oid

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

parseCertHeaderDN :: ParseASN1 [(OID, ASN1String)]
parseCertHeaderDN = sortByOID <$> onNextContainer Sequence getDNs where
	sortByOID = sortBy (\a b -> fst a `compare` fst b)
	getDNs = do
		n <- hasNext
		if n
			then liftM2 (:) parseDNOne getDNs
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
		[ UTCTime t1, UTCTime t2 ] -> return (convertTime t1, convertTime t2)
		_                          -> throwError "bad validity format"
	where convertTime (y,m,d,h,mi,s,u) =
		let day = fromGregorian (fromIntegral y) m d in
		let dtime = secondsToDiffTime (fromIntegral h * 3600 + fromIntegral mi * 60 + fromIntegral s) in
		(day, dtime, u)

parseCertHeaderSubjectPK :: ParseASN1 PubKey
parseCertHeaderSubjectPK = onNextContainer Sequence $ do
	l <- getNextContainer Sequence
	bits <- getNextBitString
	case l of
		[OID pkalg,Null] -> do
			let sig = oidPubKey pkalg
			case sig of
				PubKeyALG_RSA -> either (throwError) (return . PubKeyRSA) (parse_RSA bits)
				_             -> return $ PubKeyUnknown pkalg $ L.unpack bits
		[OID pkalg,OID _] -> do
			let sig = oidPubKey pkalg
			case sig of
				PubKeyALG_ECDSA  -> parse_ECDSA bits
				_                -> return $ PubKeyUnknown pkalg $ L.unpack bits
		[OID pkalg,Start Sequence,IntVal p,IntVal q,IntVal g,End Sequence] -> do
			let sig = oidPubKey pkalg
			case decodeASN1Stream bits of
				Right [IntVal dsapub] -> return $ PubKeyDSA $ DSA.PublicKey
					{ DSA.public_params = (p, q, g), DSA.public_y = dsapub }
				_                     -> return $ PubKeyUnknown pkalg $ L.unpack bits
		n ->
			throwError ("subject public key bad format : " ++ show n)

	where getNextBitString = getNext >>= \bs -> case bs of
		BitString bits -> return $ bitArrayGetData bits
		_              -> throwError "expecting bitstring"

parseCertExtensions :: ParseASN1 (Maybe [ExtensionRaw])
parseCertExtensions = onNextContainerMaybe (Container Context 3) (sortByOID . mapMaybe extractExtension <$> onNextContainer Sequence getSequences)
	where
		sortByOID = sortBy (\(a,_,_) (b,_,_) -> a `compare` b)
		getSequences = do
			n <- hasNext
			if n
				then getNextContainer Sequence >>= \sq -> liftM (sq :) getSequences
				else return []
		extractExtension [OID oid,Boolean True,OctetString obj] = case decodeASN1Stream obj of
			Left _  -> Nothing
			Right r -> Just (oid, True, r)
		extractExtension [OID oid,OctetString obj]              = case decodeASN1Stream obj of
			Left _  -> Nothing
			Right r -> Just (oid, False, r)
		extractExtension _                                      = Nothing

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
encodePK k@(PubKeyRSA pubkey) =
	asn1Container Sequence (asn1Container Sequence [pkalg,Null] ++ [BitString $ toBitArray bits 0])
	where
		pkalg        = OID $ pubkeyalgOID $ pubkeyToAlg k
		(Right bits) = encodeASN1Stream $ asn1Container Sequence [IntVal (RSA.public_n pubkey), IntVal (RSA.public_e pubkey)]

encodePK k@(PubKeyDSA pubkey) =
	asn1Container Sequence (asn1Container Sequence ([pkalg] ++ dsaseq) ++ [BitString $ toBitArray bits 0])
	where
		pkalg        = OID $ pubkeyalgOID $ pubkeyToAlg k
		dsaseq       = asn1Container Sequence [IntVal p,IntVal q,IntVal g]
		(p,q,g)      = DSA.public_params pubkey
		(Right bits) = encodeASN1Stream [IntVal $ DSA.public_y pubkey]

encodePK k@(PubKeyUnknown _ l) =
	asn1Container Sequence (asn1Container Sequence [pkalg,Null] ++ [BitString $ toBitArray (L.pack l) 0])
	where
		pkalg = OID $ pubkeyalgOID $ pubkeyToAlg k

encodeExts :: Maybe [ExtensionRaw] -> [ASN1]
encodeExts Nothing  = []
encodeExts (Just l) = asn1Container (Container Context 3) $ concatMap encodeExt l
	where encodeExt (oid, critical, asn1) = case encodeASN1Stream asn1 of
		Left _   -> error "cannot encode asn1 extension"
		Right bs -> asn1Container Sequence ([OID oid] ++ (if critical then [Boolean True] else []) ++ [OctetString bs])

encodeCertificateHeader :: Certificate -> [ASN1]
encodeCertificateHeader cert =
	eVer ++ eSerial ++ eAlgId ++ eIssuer ++ eValidity ++ eSubject ++ epkinfo ++ eexts
	where
		eVer      = asn1Container (Container Context 0) [IntVal (fromIntegral $ certVersion cert)]
		eSerial   = [IntVal $ certSerial cert]
		eAlgId    = asn1Container Sequence [OID (sigOID $ certSignatureAlg cert), Null]
		eIssuer   = encodeDN $ certIssuerDN cert
		(t1, t2)  = certValidity cert
		eValidity = asn1Container Sequence [UTCTime $ unconvertTime t1, UTCTime $ unconvertTime t2]
		eSubject  = encodeDN $ certSubjectDN cert
		epkinfo   = encodePK $ certPubKey cert
		eexts     = encodeExts $ certExtensions cert

		unconvertTime (day, difftime, z) =
			let (y, m, d) = toGregorian day in
			let seconds = floor $ toRational difftime in
			let h = seconds `div` 3600 in
			let mi = (seconds `div` 60) `mod` 60 in
			let s  = seconds `mod` 60 in
			(fromIntegral y,m,d,h,mi,s,z)
