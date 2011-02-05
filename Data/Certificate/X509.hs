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
	  X509(..)
	-- * Data Structure (reexported from X509Cert)
	, SignatureALG(..)
	, PubKeyALG(..)
	, PubKeyDesc(..)
	, PubKey(..)
	, ASN1StringType(..)
	, ASN1String
	, Certificate(..)
	, CertificateExts(..)

	-- * serialization from ASN1 bytestring
	, decodeCertificate
	, encodeCertificate
	) where

import Data.Word
import Data.ASN1.DER
import qualified Data.ByteString.Lazy as L
import Control.Applicative ((<$>))
import Control.Monad.Error

import Data.Certificate.X509Internal
import Data.Certificate.X509Cert

data X509 = X509 Certificate SignatureALG [Word8]
	deriving (Show,Eq)

{- | decode an X509 from a bytestring
 - the structure is the following:
 -   Certificate
 -   Certificate Signature Algorithm
 -   Certificate Signature
-}
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
