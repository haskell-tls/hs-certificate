{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
module System.X509.Win32
    ( getSystemCertificateStore
    ) where

import Foreign.Ptr
import Foreign.Storable
import Data.Word

import Control.Monad (when)
import Control.Applicative
import Control.Exception (catch)

import qualified Data.ByteString.Internal as B

import Data.X509
import Data.X509.CertificateStore
import Data.ASN1.Error

import System.Win32.Types

type HCertStore = Ptr Word8
type PCCERT_Context = Ptr Word8

foreign import stdcall unsafe "CertOpenSystemStoreW"
    c_CertOpenSystemStore :: Ptr Word8 -> LPCTSTR -> IO HCertStore
foreign import stdcall unsafe "CertCloseStore"
    c_CertCloseStore :: HCertStore -> DWORD -> IO ()

foreign import stdcall unsafe "CertEnumCertificatesInStore"
    c_CertEnumCertificatesInStore :: HCertStore -> PCCERT_Context -> IO PCCERT_Context

certOpenSystemStore :: IO HCertStore
certOpenSystemStore = withTString "ROOT" $ \cstr ->
    c_CertOpenSystemStore nullPtr cstr

certFromContext :: PCCERT_Context -> IO (Either String SignedCertificate)
certFromContext cctx = do
    ty  <- peek (castPtr cctx :: Ptr DWORD)
    p   <- peek (castPtr (cctx `plusPtr` pbCertEncodedPos) :: Ptr (Ptr BYTE))
    len <- peek (castPtr (cctx `plusPtr` cbCertEncodedPos) :: Ptr DWORD)
    process ty p len
  where process 1 p len = do
            b <- B.create (fromIntegral len) $ \dst -> B.memcpy dst p (fromIntegral len)
            return $ decodeSignedObject b
        process ty _ _ =
            return $ Left ("windows certificate store: not supported type: " ++ show ty)
        pbCertEncodedPos = alignment (undefined :: Ptr (Ptr BYTE))
        cbCertEncodedPos = pbCertEncodedPos + sizeOf (undefined :: Ptr (Ptr BYTE))

getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore = do
    store <- certOpenSystemStore
    when (store == nullPtr) $ error "no store"
    certs <- loop store nullPtr
    c_CertCloseStore store 0
    return (makeCertificateStore certs)
  where loop st ptr = do
            r <- c_CertEnumCertificatesInStore st ptr
            if r == nullPtr
                then return []
                else do
                    ecert <- certFromContext r
                    case ecert of
                        Left _     -> loop st r
                        Right cert -> (cert :) <$> (loop st r)
                    `catch` \(_ :: ASN1Error) -> loop st r
