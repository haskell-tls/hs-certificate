module System.Certificate.X509.MacOS
	( findCertificate
	) where

import Data.Certificate.X509
import Data.Certificate.PEM

findCertificate :: (X509 -> Bool) -> IO (Maybe X509)
findCertificate f = undefined
