module System.Certificate.X509.Win32
	( getSystemCertificateStore
	) where

{-
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (castPtr)

import Control.Exception (bracket, IOException)
import Control.Applicative ((<$>))

import System.Win32.Registry

import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Lazy as L

import Data.Certificate.X509
import Data.Certificate.X509.Cert

import Data.Bits
import Data.CertificateStore

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

data ReadErr =
	  Exception IOException
	| CertError String
	deriving (Show,Eq)

readCertificate dir hash = do
    b <- openValue path "Blob" fromBlob
    return $ decodeCertificate $ L.fromChunks [b]
    where path = dir ++ "\\" ++ hash

listIn dir = listSubDirectories dir >>= \hs -> (rights <$> mapM (readCertificate dir) hs)

getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore = makeCertificateStore <$> listIn defaultSystemPath
-}
import Data.CertificateStore

getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore = return (makeCertificateStore [])
