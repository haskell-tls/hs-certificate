{-# LANGUAGE CPP #-}
module Data.X509.CertificateStore
    ( CertificateStore
    , makeCertificateStore
    , readCertificateStore
    -- * Queries
    , findCertificate
    , listCertificates
    ) where

import Data.Char (isDigit, isHexDigit)
import Data.Either (rights)
import Data.List (foldl', isPrefixOf)
#if MIN_VERSION_base(4,9,0)
import           Data.Semigroup
#else
import           Data.Monoid
#endif
import Data.PEM (pemParseBS, pemContent)
import Data.X509
import qualified Data.Map as M
import Control.Applicative ((<$>))
import Control.Monad (mplus, filterM)
import System.Directory (getDirectoryContents, doesFileExist, doesDirectoryExist)
import System.FilePath ((</>))
import qualified Control.Exception as E
import qualified Data.ByteString as B


-- | A Collection of certificate or store of certificates.
data CertificateStore = CertificateStore (M.Map DistinguishedName SignedCertificate)
                      | CertificateStores [CertificateStore]

#if MIN_VERSION_base(4,9,0)
instance Semigroup CertificateStore where
    (<>) = append
#endif

instance Monoid CertificateStore where
    mempty  = CertificateStore M.empty
#if !(MIN_VERSION_base(4,11,0))
    mappend = append
#endif

append :: CertificateStore -> CertificateStore -> CertificateStore
append s1@(CertificateStore _)   s2@(CertificateStore _) = CertificateStores [s1,s2]
append    (CertificateStores l)  s2@(CertificateStore _) = CertificateStores (l ++ [s2])
append s1@(CertificateStore _)   (CertificateStores l)   = CertificateStores ([s1] ++ l)
append    (CertificateStores l1) (CertificateStores l2)  = CertificateStores (l1 ++ l2)

-- | Create a certificate store out of a list of X509 certificate
makeCertificateStore :: [SignedCertificate] -> CertificateStore
makeCertificateStore = CertificateStore . foldl' accumulate M.empty
    where accumulate m x509 = M.insert (certSubjectDN $ getCertificate x509) x509 m

-- | Find a certificate using the subject distinguished name
findCertificate :: DistinguishedName -> CertificateStore -> Maybe SignedCertificate
findCertificate dn store = lookupIn store
    where lookupIn (CertificateStore m)  = M.lookup dn m
          lookupIn (CertificateStores l) = foldl mplus Nothing $ map lookupIn l

-- | List all certificates in a store
listCertificates :: CertificateStore -> [SignedCertificate]
listCertificates (CertificateStore store) = map snd $ M.toList store
listCertificates (CertificateStores l)    = concatMap listCertificates l

-- | Create certificate store by reading certificates from file or directory
--
-- This function can be used to read multiple certificates from either
-- single file (multiple PEM formatted certificates concanated) or
-- directory (one certificate per file, file names are hashes from
-- certificate).
readCertificateStore :: FilePath -> IO (Maybe CertificateStore)
readCertificateStore path = do
    isDir  <- doesDirectoryExist path
    isFile <- doesFileExist path
    wrapStore <$> (if isDir then makeDirStore else if isFile then makeFileStore else return [])
  where
    wrapStore :: [SignedCertificate] -> Maybe CertificateStore
    wrapStore [] = Nothing
    wrapStore l  = Just $ makeCertificateStore l

    makeFileStore = readCertificates path
    makeDirStore  = do
        certFiles <- listDirectoryCerts path
        concat <$> mapM readCertificates certFiles

-- Try to read certificate from the content of a file.
--
-- The file may contains multiple certificates
readCertificates :: FilePath -> IO [SignedCertificate]
readCertificates file = E.catch (either (const []) (rights . map getCert) . pemParseBS <$> B.readFile file) skipIOError
    where
        getCert = decodeSignedCertificate . pemContent
        skipIOError :: E.IOException -> IO [SignedCertificate]
        skipIOError _ = return []

-- List all the path susceptible to contains a certificate in a directory
--
-- if the parameter is not a directory, hilarity follows.
listDirectoryCerts :: FilePath -> IO [FilePath]
listDirectoryCerts path =
    getDirContents >>= filterM doesFileExist
  where
    isHashedFile s = length s == 10
                  && isDigit (s !! 9)
                  && (s !! 8) == '.'
                  && all isHexDigit (take 8 s)
    isCert x = (not $ isPrefixOf "." x) && (not $ isHashedFile x)

    getDirContents = E.catch (map (path </>) . filter isCert <$> getDirectoryContents path) emptyPaths
            where emptyPaths :: E.IOException -> IO [FilePath]
                  emptyPaths _ = return []
