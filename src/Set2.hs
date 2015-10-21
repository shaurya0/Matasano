{-# LANGUAGE OverloadedStrings #-}
module Set2
(
    challenge9,
    )where

import Data.Word(Word32, Word8)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as BS64
import qualified Data.ByteString.Base16 as BS16
import System.IO

import qualified Blaze.ByteString.Builder as BB
import Data.Maybe
import Data.List
import Data.Ord
import Data.Tuple.Select
import Crypto.Cipher.AES
import CryptoUtils
import Data.Monoid
import Crypto.Random.DRBG
import System.Random
import Control.Monad
import qualified Data.Map as Map

-- assumption on lengths
challenge9 :: Int -> BS.ByteString -> BS.ByteString
challenge9 = pkcs7Padding


pkcs7Padding :: Int -> BS.ByteString -> BS.ByteString
pkcs7Padding n block =
    let d = n - BS.length block
        byte = fromIntegral d :: Word8
        padding = BS.pack $ take d $ repeat byte
    in BS.append block padding


challenge10 :: FilePath -> BS.ByteString -> IO BS.ByteString
challenge10 filePath initializationVector = do
    contents <- BS.readFile filePath
    let bytes = BS64.decodeLenient contents
    let initializationVector = BS.pack (take 16 $ repeat 0)
    let cipherText = cbcEncrypt initializationVector yellowSubmarine bytes
    return cipherText


challenge12 :: BS.ByteString
challenge12
    | ecb = challenge12Helper blockSize ""
    | otherwise = error "not ecb mode"
        where blockSize = detectBlockSize
              ecb = detectECBMode blockSize


challenge12Helper :: Int -> BS.ByteString -> BS.ByteString
challenge12Helper blockSize knownBytes
    | isJust result = challenge12Helper blockSize newString
    | otherwise = newString
        where   result = bruteForceByteSolve blockSize knownBytes
                newString = case result of  Just b -> BS.snoc knownBytes b
                                            otherwise -> knownBytes


yellowSubmarine :: BS.ByteString
yellowSubmarine = "YELLOW SUBMARINE"


cbcEncryptHelper :: AES -> Int -> BS.ByteString -> BS.ByteString -> [BB.Builder]
cbcEncryptHelper cipher blockSize cipherBlock plainText
    | BS.length plainText > 0 = BB.fromByteString aesBlock : cbcEncryptHelper cipher blockSize aesBlock rest
    | otherwise = []
    where
        (start, rest) = BS.splitAt blockSize plainText
        xorBlock = BS.pack $ xorByteStrings start cipherBlock
        aesBlock = encryptECB cipher xorBlock


cbcEncrypt :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString
cbcEncrypt initializationVector keyString plainText =
    let cipher = initAES keyString
        blockSize = BS.length keyString
        result = mconcat $ cbcEncryptHelper cipher blockSize initializationVector plainText
    in BB.toByteString result


data AESMode = ECB | CBC deriving (Show, Eq, Ord, Enum)

detectAESMode :: IO AESMode
detectAESMode = do
    let plainText = BS.pack $ replicate 48 (0 :: Word8)
    (cipherText, aesModeTrue) <- encryptionOracle plainText
    let cipherBlocks = blockifyBytestring 16 cipherText
    if cipherBlocks !! 1 == cipherBlocks !! 2 then return ECB else return CBC


-- assume no padding on front
detectBlockSize :: Int
detectBlockSize =
    let blockSizes = [1..32]
        blockInputs = map (\n -> BS.pack $ replicate n 0) blockSizes
        noPadLength = BS.length $ encryptionOracle2 ""
        lengths = map (\b -> (BS.length $ encryptionOracle2 b) - noPadLength ) blockInputs
        cipherTextLength = head $ filter (>0) lengths
    in cipherTextLength


detectECBMode :: Int -> Bool
detectECBMode blockSize =
    let plainText = BS.pack $ replicate (2*blockSize) (0 :: Word8)
        cipherText = encryptionOracle2 plainText
        cipherBlocks = blockifyBytestring blockSize cipherText
    in if cipherBlocks !! 0 == cipherBlocks !! 1 then True else False



bruteForceByteSolve :: Int -> BS.ByteString -> Maybe Word8
bruteForceByteSolve blockSize knownBytes =
    let zeroLength = (getPadLength blockSize knownBytes) - 1
        outputLength = zeroLength + (BS.length knownBytes) + 1
        oracleTake = BS.take outputLength . encryptionOracle2
        zeroInput = BS.pack $ replicate zeroLength 0
        input = BS.append zeroInput knownBytes
        output = oracleTake zeroInput
        guessInputs = map (BS.snoc input) allBytes
        guessOutputs = zip (map oracleTake guessInputs) allBytes
        outputByteMap = Map.fromList guessOutputs
    in Map.lookup output outputByteMap


getPadLength :: Int -> BS.ByteString -> Int
getPadLength blockSize bytes =
    let len = BS.length bytes
    in blockSize - (len `mod` blockSize)


encryptionOracle :: BS.ByteString -> IO (BS.ByteString, AESMode)
encryptionOracle plainText = do
    gen <- newStdGen
    let (randomPadLength, newGen) = randomR (5,10) gen
    (randomPadding, g1) <- genRandomBytes randomPadLength
    let builder = mconcat $ map (BB.fromByteString) [randomPadding, plainText, randomPadding]
    let randomPaddedPlainText = BB.toByteString builder
    let padLength = getPadLength 16 randomPaddedPlainText
    let newPlainText = pkcs7Padding padLength randomPaddedPlainText
    let (encryptModeInt, newGen_) = randomR (0, 1)  newGen
    let encryptMode = toEnum encryptModeInt
    (randomKey, g2) <- genRandomBytes 16
    let cipher = initAES randomKey
    cipherText <- case encryptMode of ECB -> return (encryptECB cipher newPlainText)
                                      otherwise -> (do
                                        (iv, g3) <- genRandomBytes 16
                                        return (encryptCBC cipher iv newPlainText))
    return (cipherText, encryptMode)


challenge12Appendage :: BS.ByteString
challenge12Appendage = BS64.decodeLenient "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg YnkK"


encryptionOracle2 :: BS.ByteString -> BS.ByteString
encryptionOracle2 plainText =
    let paddedPlainText = BS.append plainText challenge12Appendage
        padLength = getPadLength 16 paddedPlainText
        newPlainText = pkcs7Padding (BS.length paddedPlainText + padLength) paddedPlainText
        cipher = initAES yellowSubmarine
        cipherText = encryptECB cipher newPlainText
    in cipherText


genRandomBytes :: Int -> IO (BS.ByteString, HashDRBG)
genRandomBytes n = do
    gen <- newGenIO :: IO HashDRBG
    let Right (randomBytes, newGen) = genBytes n gen
    return (randomBytes, newGen)

