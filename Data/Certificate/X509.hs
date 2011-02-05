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
	, X509(..)
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
import Data.ASN1.DER
import Data.ASN1.Stream (getConstructedEnd)
import Data.Maybe
import Data.ByteString.Lazy (ByteString)
import Data.Text.Lazy (Text)
import qualified Data.ByteString.Lazy as L
import Control.Applicative ((<$>))
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

data CertificateExts = CertificateExts
	{ certExtKeyUsage             :: Maybe (Bool, [CertKeyUsage])
	, certExtBasicConstraints     :: Maybe (Bool, Bool)
	, certExtSubjectKeyIdentifier :: Maybe (Bool, [Word8])
	, certExtPolicies             :: Maybe (Bool)
	, certExtOthers               :: [ (OID, Bool, [ASN1]) ]
	} deriving (Show,Eq)

data ASN1StringType = UTF8 | Printable | Univ | BMP | IA5 deriving (Show,Eq)
type ASN1String = (ASN1StringType, Text)

oidCommonName, oidCountry, oidOrganization, oidOrganizationUnit :: OID
oidCommonName       = [2,5,4,3]
oidCountry          = [2,5,4,6]
oidOrganization     = [2,5,4,10]
oidOrganizationUnit = [2,5,4,11]

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

data X509 = X509 Certificate SignatureALG [Word8]
	deriving (Show,Eq)

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

newtype ParseASN1 a = P { runP :: ErrorT String (State [ASN1]) a }
	deriving (Functor, Monad, MonadError String)

runParseASN1 :: ParseASN1 a -> [ASN1] -> Either String a
runParseASN1 f s =
	case runState (runErrorT (runP f)) s of
		(Left err, _) -> Left err
		(Right r, _) -> Right r

makeASN1Sequence :: [ASN1] -> [[ASN1]]
makeASN1Sequence list =
	let (l1, l2) = getConstructedEnd 0 list in
	case l2 of
		[] -> []
		_  -> l1 : makeASN1Sequence l2

getNext :: ParseASN1 ASN1
getNext = do
	list <- P (lift get)
	case list of
		[]    -> throwError "empty"
		(h:l) -> P (lift (put l)) >> return h

getNextContainer :: ASN1ConstructionType -> ParseASN1 [ASN1]
getNextContainer ty = do
	list <- P (lift get)
	case list of
		[]    -> throwError "empty"
		(h:l) -> if h == Start ty
			then do
				let (l1, l2) = getConstructedEnd 0 l
				P (lift $ put l2) >> return l1
			else throwError "not an expected container"

onNextContainer ty f = do
	n <- getNextContainer ty
	case runParseASN1 f n of
		Left err -> throwError err
		Right r  -> return r

getNextContainerMaybe :: ASN1ConstructionType -> ParseASN1 (Maybe [ASN1])
getNextContainerMaybe ty = do
	list <- P (lift get)
	case list of
		[]    -> return Nothing
		(h:l) -> if h == Start ty
			then do
				let (l1, l2) = getConstructedEnd 0 l
				P (lift $ put l2) >> return (Just l1)
			else return Nothing

onNextContainerMaybe ty f = do
	n <- getNextContainerMaybe ty
	case n of
		Just l -> case runParseASN1 f l of
			Left err -> throwError err
			Right r  -> return $ Just r
		Nothing -> return Nothing

hasNext :: ParseASN1 Bool
hasNext = do
	list <- P (lift get)
	case list of
		[] -> return False
		_  -> return True

lookNext :: ParseASN1 ASN1
lookNext = do
	list <- P (lift get)
	case list of
		[]    -> throwError "empty"
		(h:_) -> return h

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
asn1String x                   = error ("not a print string " ++ show x)

encodeAsn1String :: ASN1String -> ASN1
encodeAsn1String (Printable, x) = PrintableString x
encodeAsn1String (UTF8, x)      = UTF8String x
encodeAsn1String (Univ, x)      = UniversalString x
encodeAsn1String (BMP, x)       = BMPString x
encodeAsn1String (IA5, x)       = IA5String x

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

{- | parse header structure of a x509 certificate. it contains
 - the version, the serial number, the issuer DN, the validity period,
 - the subject DN, and the public keys -}
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

{- | decode a X509 certificate from a bytestring -}
decodeCertificate :: L.ByteString -> Either String X509
decodeCertificate by = either (Left . show) parseRootASN1 $ decodeASN1Stream by
	where
		{- | parse root structure of a x509 certificate. this has to be a sequence of 3 objects :
		 - * the header
		 - * the signature algorithm
		 - * the signature -}
		parseRootASN1 x = runParseASN1 parseRoot x
		parseRoot = onNextContainer Sequence $ do
			cert    <- onNextContainer Sequence parseCertificate
			sigalg  <- parseSigAlg <$> getNextContainer Sequence
			sigbits <- getNext
			bits    <- case sigbits of
				BitString _ b -> return b
				_             -> throwError "signature not in right format"
			return $ X509 cert sigalg (L.unpack bits)

		parseSigAlg [ OID oid, Null ] = oidSig oid
		parseSigAlg _                 = SignatureALG_Unknown []

asn1Container ty l = [Start ty] ++ l ++ [End ty]

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

{-| encode a X509 certificate to a bytestring -}
encodeCertificate :: X509 -> L.ByteString
encodeCertificate (X509 cert sigalg sigbits) = case encodeASN1Stream rootSeq of
		Right x  -> x
		Left err -> error (show err)
	where
		esigalg   = asn1Container Sequence [OID (sigOID sigalg), Null]
		esig      = BitString 0 $ L.pack sigbits
		header    = asn1Container Sequence $ encodeCertificateHeader cert
		rootSeq   = asn1Container Sequence (header ++ esigalg ++ [esig])
