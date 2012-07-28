{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Data.Certificate.X509.Internal
        ( ParseASN1
        , runParseASN1
        , onNextContainer
        , onNextContainerMaybe
        , getNextContainer
        , getNextContainerMaybe
        , getNext
        , hasNext
        , makeASN1Sequence
        , asn1Container
        , OID
        ) where

import Data.ASN1.DER
import Data.ASN1.Stream (getConstructedEnd)
import Control.Monad.State
import Control.Monad.Error

type OID = [Integer]

newtype ParseASN1 a = P { runP :: ErrorT String (State [ASN1]) a }
        deriving (Functor, Monad, MonadError String)

runParseASN1 :: ParseASN1 a -> [ASN1] -> Either String a
runParseASN1 f s =
        case runState (runErrorT (runP f)) s of
                (Left err, _) -> Left err
                (Right r, _) -> Right r

getNext :: ParseASN1 ASN1
getNext = do
        list <- P (lift get)
        case list of
                []    -> throwError "empty"
                (h:l) -> P (lift (put l)) >> return h

getNextContainer :: ASN1ConstructionType -> ParseASN1 [ASN1]
getNextContainer ty = do
        list <- P (lift get)
        case list of
                []    -> throwError "empty"
                (h:l) -> if h == Start ty
                        then do
                                let (l1, l2) = getConstructedEnd 0 l
                                P (lift $ put l2) >> return l1
                        else throwError "not an expected container"


onNextContainer :: ASN1ConstructionType -> ParseASN1 a -> ParseASN1 a
onNextContainer ty f = do
        n <- getNextContainer ty
        case runParseASN1 f n of
                Left err -> throwError err
                Right r  -> return r

getNextContainerMaybe :: ASN1ConstructionType -> ParseASN1 (Maybe [ASN1])
getNextContainerMaybe ty = do
        list <- P (lift get)
        case list of
                []    -> return Nothing
                (h:l) -> if h == Start ty
                        then do
                                let (l1, l2) = getConstructedEnd 0 l
                                P (lift $ put l2) >> return (Just l1)
                        else return Nothing

onNextContainerMaybe :: ASN1ConstructionType -> ParseASN1 a -> ParseASN1 (Maybe a)
onNextContainerMaybe ty f = do
        n <- getNextContainerMaybe ty
        case n of
                Just l -> case runParseASN1 f l of
                        Left err -> throwError err
                        Right r  -> return $ Just r
                Nothing -> return Nothing

hasNext :: ParseASN1 Bool
hasNext = do
        list <- P (lift get)
        case list of
                [] -> return False
                _  -> return True

asn1Container :: ASN1ConstructionType -> [ASN1] -> [ASN1]
asn1Container ty l = [Start ty] ++ l ++ [End ty]

makeASN1Sequence :: [ASN1] -> [[ASN1]]
makeASN1Sequence list =
        let (l1, l2) = getConstructedEnd 0 list in
        case l2 of
                [] -> []
                _  -> l1 : makeASN1Sequence l2

