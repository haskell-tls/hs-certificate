module System.Certificate.X509.Win32
	( getSystemPath
	, readAll
	, findCertificate
	) where

import System.Win32.Registry
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B

defaultSystemPath :: FilePath
defaultSystemPath = "SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates"

listSubDirectories path = bracket openKey regCloseKey regEnumKeys
	where openKey = regOpenKeyEx hKEY_LOCAL_MACHINE path kEY_ALL_ACCESS

openValue path key toByteS = bracket openKey regCloseKey $ \hkey -> allocaBytes 4096 $ \mem -> do
		regQueryValueEx hkey key mem 4096 >>= toByteS mem
	where openKey = regOpenKeyEx hKEY_LOCAL_MACHINE path kEY_QUERY_VALUE

fromBlob mem ty
	| ty == rEG_BINARY = do
		len <- B.c_strlen mem
		B.create len (\bptr -> B.memcpy bptr mem len)
	| otherwise        = error "certificate blob have unexpected type"

getSystemPath :: IO FilePath
getSystemPath = undefined

readAll :: IO [Either ReadErr X509]
readAll = undefined

findCertificate :: (X509 -> Bool) -> IO (Maybe X509)
findCertificate f = undefined
