module Data.CertificateStore
    ( CertificateStore
    , makeCertificateStore
    -- * Queries
    , findCertificate
    , listCertificates
    ) where

import Data.List (foldl')
import Data.Monoid
import Data.Certificate.X509
import qualified Data.Map as M
import Control.Monad (mplus)

-- | A Collection of certificate or store of certificates.
data CertificateStore = CertificateStore (M.Map DistinguishedName X509)
                      | CertificateStores [CertificateStore]

instance Monoid CertificateStore where
    mempty  = CertificateStore M.empty
    mappend s1@(CertificateStore _)   s2@(CertificateStore _) = CertificateStores [s1,s2]
    mappend    (CertificateStores l)  s2@(CertificateStore _) = CertificateStores (l ++ [s2])
    mappend s1@(CertificateStore _)   (CertificateStores l)   = CertificateStores ([s1] ++ l)
    mappend    (CertificateStores l1) (CertificateStores l2)  = CertificateStores (l1 ++ l2)

-- | Create a certificate store out of a list of X509 certificate
makeCertificateStore :: [X509] -> CertificateStore
makeCertificateStore = CertificateStore . foldl' accumulate M.empty
    where accumulate m x509 = M.insert (certSubjectDN $ x509Cert x509) x509 m

-- | Find a certificate using the subject distinguished name
findCertificate :: DistinguishedName -> CertificateStore -> Maybe X509
findCertificate dn store = lookupIn store
    where lookupIn (CertificateStore m)  = M.lookup dn m
          lookupIn (CertificateStores l) = foldl mplus Nothing $ map lookupIn l

-- | List all certificates in a store
listCertificates :: CertificateStore -> [X509]
listCertificates (CertificateStore store) = map snd $ M.toList store
listCertificates (CertificateStores l)    = concatMap listCertificates l
