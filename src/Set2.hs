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
import Data.List
import Data.Ord
import Data.Tuple.Select
import Crypto.Cipher.AES
import CryptoUtils
import Data.Monoid

-- assumption on lengths
challenge9 :: Int -> BS.ByteString -> BS.ByteString
challenge9 n block =
    let d = n - BS.length block
        byte = fromIntegral d :: Word8
        padding = BS.pack $ take d $ repeat byte
    in BS.append block padding


challenge10 :: FilePath -> BS.ByteString -> IO BS.ByteString
challenge10 filePath initializationVector = do
    contents <- BS.readFile filePath
    let bytes = BS64.decodeLenient contents

    error "todo"

yellowSubmarine :: BS.ByteString
yellowSubmarine = "YELLOW SUBMARINE"


cbcEncrypt :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString
cbcEncrypt initializationVector keyString plainText =
    let cipher = initAES keyString
        cipherTextECB = encryptECB cipher plainText
        cipherBlocks = blockifyBytestring 16 cipherTextECB
    in error "todo"
