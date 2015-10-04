{-# LANGUAGE OverloadedStrings #-}
module Set1
(
    challenge1,
    challenge2,
    challenge3,
    challenge4,
    challenge5,
    challenge6,
    challenge7,
    challenge8
    )where

import Data.Word(Word32, Word8)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as BS64
import qualified Data.ByteString.Base16 as BS16
import System.IO

import Data.List
import Data.Ord
import Data.Tuple.Select
import Crypto.Cipher.AES

import CryptoUtils


challenge1 :: BS.ByteString -> BS.ByteString
challenge1 = hexToBase64


challenge2 :: BS.ByteString -> BS.ByteString -> BS.ByteString
challenge2 key hexStr = BS16.encode $ fixedXOR (bs16Decode key) (bs16Decode hexStr)


challenge3 :: BS.ByteString -> (Word8, BS.ByteString)
challenge3 hexStr =
    let bytes = bs16Decode hexStr
        result = xorCipherMaxScore bytes
    in (sel1 result, sel3 result)


-- assumption on only one result
challenge4 :: FilePath -> IO (Word8, BS.ByteString, Int)
challenge4 filePath = do
    contents <- BS.readFile filePath
    let fileLines = BS.split newLine contents
    let results = detectCipher fileLines
    let ((cipher, _, str), lineIdx) = head results
    return (cipher, str, lineIdx)


challenge5 :: BS.ByteString -> BS.ByteString -> BS.ByteString
challenge5 key str = BS16.encode $ repeatingKeyXor key str


challenge6 :: FilePath -> IO BS.ByteString
challenge6 filePath = do
    contents <- BS.readFile filePath
    let bytes = BS64.decodeLenient contents
    let key = breakRepeatingKeyXor bytes
    return key


challenge7 :: FilePath -> IO BS.ByteString
challenge7 filePath = do
    contents <- BS.readFile filePath
    let bytes = BS64.decodeLenient contents
    let cipher = initAES keyString
    let result = decryptECB cipher contents
    return result


challenge8 :: FilePath -> IO Int
challenge8 filePath = do
    contents <- BS.readFile filePath
    let fileLines = BS.split newLine contents
    let linesAsBytes = map bs16Decode fileLines
    let scores = zip [1.. length fileLines] $ map challenge8Helper linesAsBytes
    return $ fst $ maximumBy (comparing snd) scores


keyString :: BS.ByteString
keyString = "YELLOW SUBMARINE"


challenge8Helper :: BS.ByteString -> Int
challenge8Helper bytes =
    let blocks = blockifyBytestring 16 bytes
        blockPairs = pairs blocks
        score = foldr (\(a,b) acc -> if a == b then acc + 1 else acc) 0 blockPairs
    in score
