module System.Certificate.X509.Win32
	( findCertificate
	) where

import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (castPtr)

import Control.Exception (bracket, IOException)
import Control.Applicative ((<$>))

import System.Win32.Registry

import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Lazy as L

import Data.Certificate.X509
import Data.Certificate.X509Cert

import Data.Bits

defaultSystemPath :: FilePath
defaultSystemPath = "SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates"

listSubDirectories path = bracket openKey regCloseKey regEnumKeys
	where openKey = regOpenKeyEx hKEY_LOCAL_MACHINE path (kEY_ENUMERATE_SUB_KEYS .|. kEY_READ)

openValue path key toByteS = bracket openKey regCloseKey $ \hkey -> allocaBytes 4096 $ \mem -> do
		regQueryValueEx hkey key mem 4096 >>= toByteS mem
	where openKey = regOpenKeyEx hKEY_LOCAL_MACHINE path kEY_QUERY_VALUE

fromBlob mem ty
	| ty == rEG_BINARY = do
		len <- B.c_strlen (castPtr mem)
		B.create (fromIntegral len) (\bptr -> B.memcpy bptr mem len)
	| otherwise        = error "certificate blob have unexpected type"

getSystemPath :: IO FilePath
getSystemPath = undefined

data ReadErr =
	  Exception IOException
	| CertError String
	deriving (Show,Eq)

findCertificate :: (X509 -> Bool) -> IO (Maybe X509)
findCertificate f = do
	hashes <- listSubDirectories defaultSystemPath
	loop hashes
	where
		readCertificate path = do
			b <- openValue path "Blob" fromBlob
			return $ decodeCertificate $ L.fromChunks [b]

		loop []     = return Nothing
		loop (x:xs) = do
			cert <- readCertificate (defaultSystemPath ++ "\\" ++ x)
			case cert of
				Left _ -> loop xs
				Right x509 -> if f x509 then return $ Just x509 else loop xs
