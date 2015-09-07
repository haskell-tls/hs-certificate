-- |
-- Module      : Data.X509.Validation.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Validation types
module Data.X509.Validation.Types
    ( ServiceID
    , HostName
    ) where

import Data.ByteString (ByteString)

type HostName = String

-- | identification of the connection consisting of the
-- fully qualified host name (e.g. www.example.com) and
-- an optional suffix.
--
-- The suffix is not used by the validation process, but
-- is used by the optional cache to identity certificate per service
-- on a specific host. For example, one might have a different
-- certificate on 2 differents ports (443 and 995) for the same host.
--
-- for TCP connection, it's recommended to use: :port, or :service for the suffix.
--
type ServiceID = (HostName, ByteString)
