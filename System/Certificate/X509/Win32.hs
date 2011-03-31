module System.Certificate.X509.Win32
	( getSystemPath
	, readAll
	, findCertificate
	) where

import System.Win32.Registry

defaultSystemPath :: FilePath
defaultSystemPath = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates"

getSystemPath :: IO FilePath
getSystemPath = undefined

readAll :: IO [Either ReadErr X509]
readAll = undefined

findCertificate :: (X509 -> Bool) -> IO (Maybe X509)
findCertificate f = undefined
