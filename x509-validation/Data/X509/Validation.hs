-- |
-- Module      : Data.X509.Validation
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Certificate checks and validations routines
--
-- Follows RFC5280 / RFC6818
--
module Data.X509.Validation
    (
    ) where

import Data.X509
import Data.Time.Clock

import Data.X509.Validation.Signature

data FailedReason =
      UnknownCriticalExtension -- ^ certificate contains an unknown critical extension
    | Expired                  -- ^ validity ends before checking time
    | InFuture                 -- ^ validity starts after checking time
    | SelfSigned               -- ^ certificate is self signed
    | UnknownCA                -- ^ unknown Certificate Authority (CA)
    | NotAllowedToSign         -- ^ certificate is not allowed to sign (not a CA)
    | SignatureFailed          -- ^ signature failed
    deriving (Show,Eq)

data Checks = Checks
    { checkValidity :: Bool
    } deriving (Show,Eq)

defaultChecks = Checks
    { checkValidity = True
    }

validate :: Checks -> CertificateChain -> IO [FailedReason]
validate checks certificateChain = do
    time <- getCurrentTime
    doCheck 
  where doCheck = return []
