module System.X509.Common
  ( withOpenSSLCertEnv
  )
where

import Data.Foldable (asum)
import Data.Maybe (catMaybes)
import Data.Monoid (mconcat)
import Data.X509.CertificateStore
import System.Environment (lookupEnv)

getOpenSslEnvs :: IO (Maybe String)
getOpenSslEnvs =
  asum
    <$> traverse
      lookupEnv
      [ "SSL_CERT_FILE",
        "SSL_CERT_DIR" 
      ]

withOpenSSLCertEnv :: IO CertificateStore -> IO CertificateStore
withOpenSSLCertEnv defaultStore = do
  overrideCertPaths <- getOpenSslEnvs
  case overrideCertPaths of
    Nothing -> defaultStore
    Just certPath -> mconcat . catMaybes <$> mapM readCertificateStore [certPath]