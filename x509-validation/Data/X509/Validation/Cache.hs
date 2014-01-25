-- |
-- Module      : Data.X509.Validation.Cache
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Validation cache
--
-- Define all the types necessary for the validation cache,
-- and some simples instances of cache mechanism
module Data.X509.Validation.Cache
    (
    -- * Cache for validation
      ValidationCacheResult(..)
    , ValidationCacheQueryCallback
    , ValidationCacheAddCallback
    , ValidationCache(..)
    -- * Simple instances of cache mechanism
    , exceptionValidationCache
    , tofuValidationCache
    ) where

import Control.Concurrent
import Data.Default.Class
import Data.X509
import Data.X509.Validation.Types
import Data.X509.Validation.Fingerprint

-- | The result of a cache query
data ValidationCacheResult =
      ValidationCachePass          -- ^ cache allow this fingerprint to go through
    | ValidationCacheDenied String -- ^ cache denied this fingerprint for further validation
    | ValidationCacheUnknown       -- ^ unknown fingerprint in cache
    deriving (Show,Eq)

-- | Validation cache query callback type
type ValidationCacheQueryCallback = ServiceID          -- ^ connection's identification
                                 -> Fingerprint        -- ^ fingerprint of the leaf certificate
                                 -> Certificate        -- ^ leaf certificate
                                 -> IO ValidationCacheResult -- ^ return if the operation is succesful or not

-- | Validation cache callback type
type ValidationCacheAddCallback = ServiceID   -- ^ connection's identification
                               -> Fingerprint -- ^ fingerprint of the leaf certificate
                               -> Certificate -- ^ leaf certificate
                               -> IO ()

-- | All the callbacks needed for querying and adding to the cache.
data ValidationCache = ValidationCache
    { cacheQuery :: ValidationCacheQueryCallback -- ^ cache querying callback
    , cacheAdd   :: ValidationCacheAddCallback   -- ^ cache adding callback
    }

instance Default ValidationCache where
    def = exceptionValidationCache []

-- | create a simple constant cache that list exceptions to the certification
-- validation. Typically this is use to allow self-signed certificates for
-- specific use, with out-of-bounds user checks.
--
-- No fingerprints will be added after the instance is created.
--
-- The underlying structure for the check is kept as a list, as
-- usually the exception list will be short, but when the list go above
-- a dozen exceptions it's recommended to use another cache mechanism with
-- a faster lookup mechanism (hashtable, map, etc).
--
-- Note that only one fingerprint is allowed per ServiceID, for other use,
-- another cache mechanism need to be use.
exceptionValidationCache :: [(ServiceID, Fingerprint)] -> ValidationCache
exceptionValidationCache fingerprints =
    ValidationCache (queryListCallback fingerprints)
                    (\_ _ _ -> return ())

-- | Trust on first use (TOFU) cache with an optional list of exceptions
--
-- this is similar to the exceptionCache, except that after
-- each succesfull validation it does add the fingerprint
-- to the database. This prevent any further modification of the
-- fingerprint for the remaining
tofuValidationCache :: [(ServiceID, Fingerprint)] -- ^ a list of exceptions
                    -> IO ValidationCache
tofuValidationCache fingerprints = do
    l <- newMVar fingerprints
    return $ ValidationCache (\s f c -> readMVar l >>= \list -> (queryListCallback list) s f c)
                             (\s f _ -> modifyMVar_ l (\list -> return ((s,f) : list)))

-- | a cache query function working on list.
-- don't use when the list grows a lot.
queryListCallback :: [(ServiceID, Fingerprint)] -> ValidationCacheQueryCallback
queryListCallback list = query
  where query serviceID fingerprint _ = return $
            case lookup serviceID list of
                Nothing                   -> ValidationCacheUnknown
                Just f | fingerprint == f -> ValidationCachePass
                       | otherwise        -> ValidationCacheDenied (show serviceID ++ " expected " ++ show f ++ " but got: " ++ show fingerprint)

