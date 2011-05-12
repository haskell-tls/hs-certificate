module System.Certificate.X509.MacOS
	( getSystemPath
	, readAll
	, findCertificate
	) where
import Data.Certificate.X509
import Control.Exception

getSystemPath :: IO FilePath
getSystemPath = undefined

data ReadErr =
	  Exception IOException
	| CertError String
	deriving (Show,Eq)


readAll :: IO [Either ReadErr X509]
readAll = undefined

findCertificate :: (X509 -> Bool) -> IO (Maybe X509)
findCertificate f = undefined
