{-# LANGUAGE OverloadedStrings #-}
module CryptoUtils
(
    bs16Decode,
    hexToBase64,
    fixedXOR,
    englishFreqs,
    allBytes,
    newLine,
    scoreString,
    xorByteStrings,
    xorCipherAllBytes,
    xorCipherMaxScore,
    detectCipher,
    repeatingKeyXor,
    hammingDistance,
    keySizeValues,
    pairs,
    keySizeEditDistance,
    blockifyBytestring,
    breakRepeatingKeyXor
    )where


import Data.Word(Word32, Word8)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as BS64
import qualified Data.ByteString.Base16 as BS16

import Data.List
import Data.Bits
import Data.Ord
import Data.Maybe
import Data.Tuple.Select
import qualified Data.Map as M
import Crypto.Cipher.AES



bs16Decode :: BS.ByteString -> BS.ByteString
bs16Decode = fst . BS16.decode

hexToBase64 :: BS.ByteString -> BS.ByteString
hexToBase64 = BS64.encode . bs16Decode


fixedXOR :: BS.ByteString -> BS.ByteString -> BS.ByteString
fixedXOR key bytes = BS.pack $ BS.zipWith xor key bytes

englishFreqs :: M.Map Word8 Double
englishFreqs = M.fromList [(32, 0.1918182), (97, 0.0651738), (98, 0.0124248), (99, 0.0217339), (100, 0.0349835), (101, 0.1041442), (102, 0.0197881), (103, 0.0158610), (104, 0.0492888), (105, 0.0558094), (106, 0.0009033), (107, 0.0050529), (108, 0.0331490), (109, 0.0202124), (110, 0.0564513), (111, 0.0596302), (112, 0.0137645), (113, 0.0008606), (114, 0.0497563), (115, 0.0515760), (116, 0.0729357), (117, 0.0225134), (118, 0.0082903), (119, 0.0171272), (120, 0.0013692), (121, 0.0145984), (122, 0.0007836)]

allBytes :: [Word8]
allBytes = [0..255]

newLine :: Word8
newLine = 10


scoreString :: BS.ByteString -> Double
scoreString = BS.foldr (\w acc ->
    let byteScore = fromMaybe 0.0 (M.lookup w englishFreqs)
    in acc + byteScore ) 0.0


xorCipherAllBytes :: BS.ByteString -> [BS.ByteString]
xorCipherAllBytes bytes = map (\b -> BS.map (xor b) bytes) allBytes


xorByteStrings :: BS.ByteString -> BS.ByteString -> [Word8]
xorByteStrings bytes1 bytes2 = map (uncurry xor) $ BS.zip bytes1 bytes2

xorCipherMaxScore :: BS.ByteString -> (Word8, Double, BS.ByteString)
xorCipherMaxScore bytes =
    let xorStrings = xorCipherAllBytes bytes
        scores = map scoreString xorStrings
    in maximumBy (comparing sel2) $ zip3 allBytes scores xorStrings



detectCipher :: [BS.ByteString] -> [((Word8, Double, BS.ByteString), Int)]
detectCipher fileLines =
    let idx = [1..]
        scoreIdx = zip (map xorCipherMaxScore fileLines) idx
    in filter (\(a, b) -> sel2 a > 0) scoreIdx



repeatingKeyXor :: BS.ByteString -> BS.ByteString -> BS.ByteString
repeatingKeyXor key str
    | BS.length str > 0 = BS.append encryptStr (repeatingKeyXor key rest)
    | otherwise = ""
    where
        len = BS.length key
        (start, rest) = BS.splitAt len str
        encryptStr = BS.pack $ xorByteStrings start key


hammingDistance :: BS.ByteString -> BS.ByteString -> Int
hammingDistance str1 str2 =
    let xorStr = xorByteStrings str1 str2
    in sum $ map popCount xorStr

keySizeValues :: [Int]
keySizeValues = [2..40]

pairs :: [t] -> [(t, t)]
pairs xs = [(x1, x2) | (x1:xs1) <- tails xs, x2 <- xs1]

keySizeEditDistance :: Int -> BS.ByteString -> (Int, Double)
keySizeEditDistance keySize bytes =
    let blocks = take 4 $ blockifyBytestring keySize bytes
        blockPairs = pairs blocks
        c = 1.0/ fromIntegral keySize
        normalizedEditDistances = map (\(p1,p2) -> fromIntegral (hammingDistance p1 p2)*c) blockPairs
        len = fromIntegral $ length normalizedEditDistances
        score = sum normalizedEditDistances / len
    in (keySize, score)


blockifyBytestring ::  Int -> BS.ByteString -> [BS.ByteString]
blockifyBytestring chunkSize bytes
    | BS.length bytes > 0 = start : blockifyBytestring chunkSize rest
    | otherwise = []
    where
        (start, rest) = BS.splitAt chunkSize bytes


breakRepeatingKeyXor :: BS.ByteString -> BS.ByteString
breakRepeatingKeyXor bytes =
    let keyEditDistances = map (`keySizeEditDistance` bytes) keySizeValues
        keySize = fst $ minimumBy (comparing snd) keyEditDistances
        blocks = blockifyBytestring keySize bytes
        transposedBlocks = BS.transpose blocks
        maxCipherScores = map xorCipherMaxScore transposedBlocks
        xorCiphers = map sel1 maxCipherScores
    in BS.pack xorCiphers
