module Main where

import System.Process

data KeyType = RSA | DSA | ECDSA
    deriving (Show,Eq)

data OpenSSLKey = OpenSSLKey KeyType String Int
    deriving (Show,Eq)

data OpenSSLCSR = OpenSSLCSR
    { csrPrivateKey :: OpenSSLKey
    , csrFile       :: String
    , csrInfo       :: OpenSSLCSRInfo
    } deriving (Show,Eq)

data OpenSSLCSRInfo = OpenSSLCSRInfo
    { csrCountryName       :: String
    , csrState             :: String
    , csrLocality          :: String
    , csrOrganizationName  :: String
    , csrOrganizationUName :: String
    , csrCommonName        :: String
    , csrEmailAddress      :: String
    } deriving (Show,Eq)

createKey (OpenSSLKey keyType keyName keyBits) =
    case keyType of
        RSA   -> readProcess "openssl" ["genrsa","-out",keyName,show keyBits] ""
        DSA   -> readProcess "openssl" ["dsaparam","-genkey", show keyBits,"-out",keyName] ""
        ECDSA -> undefined

createPub (OpenSSLKey keyType keyName _) pubName =
    case keyType of
        RSA   -> readProcess "openssl" [ "rsa", "-in", keyName, "-pubout", "-out", pubName ] ""
        DSA   -> readProcess "openssl" [ "dsa", "-in", keyName, "-pubout", "-out", pubName ] ""
        _     -> undefined

createCSR (OpenSSLCSR (OpenSSLKey _ keyName _) csrFile csrInfo) =
    readProcess "openssl" ["req", "-new", "-key", keyName, "-out", csrFile] input
  where input = unlines
            [ csrCountryName csrInfo
            , csrState csrInfo
            , csrLocality csrInfo
            , csrOrganizationName csrInfo
            , csrOrganizationUName csrInfo
            , csrCommonName csrInfo
            , csrEmailAddress csrInfo
            , ""
            , ""
            ]

createCert csrFile (OpenSSLKey _ keyName _) certFile =
    readProcess "openssl" [ "x509", "-req", "-days", "365", "-in", csrFile, "-signkey", keyName, "-out", certFile ] ""

defaultCSRInfo = OpenSSLCSRInfo "AU" "" "Somewhere" "MyOrganization" "MyOrganizationUname" "my.common.name" "postmaster@common.name"

main = do
    let rsaKey = OpenSSLKey RSA "rsa.priv" 1024
        dsaKey = OpenSSLKey DSA "dsa.priv" 1024
    createKey rsaKey
    createKey dsaKey

    createPub rsaKey "rsa.pub"
    createPub dsaKey "dsa.pub"

    createCSR (OpenSSLCSR dsaKey "cert.csr" defaultCSRInfo)

    createCert "cert.csr" dsaKey "cert.dsa.x509"
    createCert "cert.csr" rsaKey "cert.rsa.x509"
