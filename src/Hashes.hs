{-# LANGUAGE DeriveDataTypeable #-}
module Hashes(
         HashInfo(..)
       , hashSHA1
       , hashSHA224, hashSHA256, hashSHA384, hashSHA512
       )
 where

import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.SHA

data HashInfo = HashInfo {
    name           :: String
  , algorithmIdent :: ByteString
  , hashFunction   :: ByteString -> ByteString
  }

instance Show HashInfo where
  show = name


hashSHA1 :: HashInfo
hashSHA1 = HashInfo {
   name           = "SHA1"
 , algorithmIdent = BS.pack [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,
                             0x02,0x1a,0x05,0x00,0x04,0x14]
 , hashFunction   = bytestringDigest . sha1
 }

hashSHA224 :: HashInfo
hashSHA224 = HashInfo {
   name           = "SHA224"
 , algorithmIdent = BS.pack [0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
                             0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,
                             0x1c]
 , hashFunction   = bytestringDigest . sha224
 }

hashSHA256 :: HashInfo
hashSHA256 = HashInfo {
   name           = "SHA256"
 , algorithmIdent = BS.pack [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
                             0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,
                             0x20]
 , hashFunction   = bytestringDigest . sha256
 }

hashSHA384 :: HashInfo
hashSHA384 = HashInfo {
   name           = "SHA384"
 , algorithmIdent = BS.pack [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
                             0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,
                             0x30]
 , hashFunction   = bytestringDigest . sha384
 }

hashSHA512 :: HashInfo
hashSHA512 = HashInfo {
   name           = "SHA512"
 , algorithmIdent  = BS.pack [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
                              0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,
                              0x40]
 , hashFunction   = bytestringDigest . sha512
 }
