module RSA(
         PrivateKey(..)
       , PublicKey(..)
       , generateKeyPair
       , sign
       , verify
       , os2ip, i2osp
       , rsa_vp1, rsa_sp1
       )
 where

import Crypto.Random
import Crypto.Types.PubKey.RSA
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS

import Hashes
import Primitives

generateKeyPair :: CryptoRandomGen g =>
                   g -> Int ->
                   (PublicKey, PrivateKey, g)
generateKeyPair g sizeBits = do
  let keyLength  = fromIntegral (sizeBits `div` 8)
      (p, q, g') = generatePQ g keyLength
      n          = p * q
      phi        = (p - 1) * (q - 1)
      e          = 65537
      d          = modMulInv e phi
      publicKey  = PublicKey keyLength n e
      privateKey = PrivateKey publicKey d p q 0 0 0
    in (publicKey, privateKey, g')


-- rsa pkcs v1.5 signature
sign :: HashInfo -> PrivateKey -> ByteString -> ByteString
sign hi k m =
  let em  = encode hi m (private_size k) -- Step 1
      m_i = os2ip em                                  -- Step 2a
      s   = rsa_sp1 (private_n k) (private_d k) m_i      -- Step 2b
      sig = i2osp s (private_size k)                     -- Step 2c
    in sig

-- rsa pkcs v1.5 signature
verify :: HashInfo -> PublicKey -> ByteString -> ByteString -> Bool
verify hi k m s
  | BS.length s /= fromIntegral (public_size k)  = False -- wrong length
  | otherwise                                    =
      let s_i = os2ip s                                  -- Step 2a
          m_i = rsa_vp1 (public_n k) (public_e k) s_i       -- Step 2b
          em  = i2osp m_i (public_size k)                   -- Step 2c
          em' = encode hi m (public_size k) -- Step 3
        in (em == em')

-- signature generation
rsa_sp1 :: Integer -> Integer -> Integer -> Integer
rsa_sp1 n _ m | (m < 0) || (m >= n) = error "Message represented out of range"
rsa_sp1 n d m                       = (modExp m d n)

-- signature verification
rsa_vp1 :: Integer -> Integer -> Integer -> Integer
rsa_vp1 n _ s | (s < 0) || (s >= n) = error "Cipher represented out of range"
rsa_vp1 n e s                       = (modExp s e n)

-- EMSA PKCS1 1.5 encoding
encode :: HashInfo -> ByteString -> Int -> ByteString
encode (HashInfo _ ident hash) m emLen
  | fromIntegral emLen < (tLen + 1) = error "Message too short"
  | otherwise                       = em
 where
  h = hash m
  t = ident `BS.append` h
  tLen = BS.length t
  ps = BS.replicate (fromIntegral emLen - tLen - 3) 0xFF
  em = BS.concat [BS.singleton 0x00,BS.singleton 0x01,ps,BS.singleton 0x00,t]

-- keypair number generator
generatePQ :: CryptoRandomGen g => g -> Int -> (Integer, Integer, g)
generatePQ g len
  | len < 2   = error "Key size too small"
  | otherwise = let (baseP, g')  = randPrime g  (len `div` 2)
                    (baseQ, g'') = randPrime g' (len - (len `div` 2))
                  in case () of
                      () | baseP == baseQ -> generatePQ g'' len
                         | baseP <  baseQ -> (baseQ, baseP, g'')
                         | otherwise      -> (baseP, baseQ, g'')

