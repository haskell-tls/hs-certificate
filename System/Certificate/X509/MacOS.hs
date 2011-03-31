module System.Certificate.X509.MacOS
	( getSystemPath
	, readAll
	, findCertificate
	) where

getSystemPath :: IO FilePath
getSystemPath = undefined

readAll :: IO [Either ReadErr X509]
readAll = undefined

findCertificate :: (X509 -> Bool) -> IO (Maybe X509)
findCertificate f = undefined
