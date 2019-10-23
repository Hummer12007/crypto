import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Test.QuickCheck
import Crypto.Random

import Test.Framework (defaultMain)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import RSA
import Hashes

type KeyPairs = [(PublicKey, PrivateKey)]

numRandomKeyPairs :: Int
numRandomKeyPairs = length keySizes * 2

keySizes :: [Int]
keySizes = [128,256,512]--,1024,2048,4096]

getRandom :: IO SystemRandom
getRandom = newGenIO

main :: IO ()
main = do
  g <- getRandom
  let (keys, _) = buildRandomKeyPairs g (cycle keySizes) numRandomKeyPairs
  defaultMain
    [ testProperty "Can roundtrip from Integer to BS and back" prop_i2o2iIdent
    , testProperty "Can roundtrip from BS to Integer and back" prop_o2i2oIdent
    , testProperty "Can roundtrip RSA's SP and VP functions"
                     (prop_spVpIdent keys)
    , testProperty "Checking verify verifies sign" (propSignVerifies keys)
    ]

buildRandomKeyPairs :: CryptoRandomGen g => g -> [Int] -> Int -> (KeyPairs, g)
buildRandomKeyPairs g _              0 = ([], g)
buildRandomKeyPairs _ []             _ = error "The world has gone insane."
buildRandomKeyPairs g (keySize:rest) x =
  let (pub, priv, g') = generateKeyPair g keySize
      (acc, g'') = buildRandomKeyPairs g' rest (x - 1)
    in ((pub, priv) : acc, g'')

instance Arbitrary ByteString where
    arbitrary = BS.pack `fmap` arbitrary

instance Arbitrary HashInfo where
  arbitrary = elements [hashSHA1, hashSHA224,
                       hashSHA256, hashSHA384, hashSHA512]

data KeyPairIdx = KPI Int
 deriving (Show)

instance Arbitrary KeyPairIdx where
  arbitrary = KPI `fmap` choose (0, numRandomKeyPairs - 1)

prop_i2o2iIdent :: Positive Integer -> Bool
prop_i2o2iIdent px =
  let x' = i2osp x l
    in os2ip x' == x
 where
  x = getPositive px
  l = findLen 1 256
  --
  findLen b t | t > x     = b
              | otherwise = findLen (b + 1) (t * 256)

prop_o2i2oIdent :: ByteString -> Bool
prop_o2i2oIdent bs = i2osp (os2ip bs) (fromIntegral (BS.length bs)) == bs

prop_spVpIdent :: KeyPairs -> KeyPairIdx ->
                  Positive Integer ->
                  Bool
prop_spVpIdent kps (KPI idx) x =
  let n  = public_n pub
      e  = public_e pub
      d  = private_d priv
      m  = getPositive x `mod` n
      sp = rsa_sp1 n d m
      m' = rsa_vp1 n e sp
    in (m == m')
 where (pub, priv) = kps !! idx

propSignVerifies :: KeyPairs -> KeyPairIdx ->
                         HashInfo -> ByteString ->
                         Property
propSignVerifies kps (KPI idx) hash m = wellSized ==>
  let sig = sign hash priv m
    in verify hash pub m sig
 where
  (pub, priv) = kps !! idx
  wellSized = fromIntegral (public_size pub) > (algSize + hashLen + 1)
  algSize   = BS.length (algorithmIdent hash)
  hashLen   = BS.length (hashFunction hash BS.empty)
