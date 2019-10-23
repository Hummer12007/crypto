module Primitives
  ( isPrime
  , isPrimeU
  , factor
  , factors
  , moebius
  , euler
  , jacobi
  , jacobi_
  , legendre
  , legendre_
  , randPrime
  , modExp
  , extEuclid
  , modMulInv
  , divides
  , os2ip
  , i2osp
  ) where

import Control.Arrow

import Data.Bits
import Data.List
import Data.Ratio
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS

import System.IO.Unsafe
import System.Random
import Crypto.Random

--- LAB PLAN
-- [x] EULER
-- [x] MOEBIUS
-- [x] LEGENDRE SYMBOL
-- [x] JACOBI SYMBOL
-- [x] PRIMALITY: RABIN-MILLER
-- [x] FACTORIZATION: RHO-POLLARD
-- [x] DISCRETE LOGARITHM: SHANKS
-- [x] CRYPTOSYSTEM: RSA
-- [x] CRYPTOSYSTEM: EC ELGAMAL

--- PRIMALITY TESTING: RABIN-MILLER

isPrime :: Integer -> IO Bool
isPrime n = do
  g <- newStdGen
  return (millerRabin g n)

millerRabin :: RandomGen g => g -> Integer -> Bool
millerRabin g n
  | even n = n == 2
  | otherwise = all (flip isPseudoPrime n) $ take 50 (randomRs (2, n - 2) g)

isPseudoPrime :: Integer -> Integer -> Bool
isPseudoPrime base n =
  let (s, d) = extractPowersOf 2 (n - 1)
  in divides n (modExp base d n - 1) ||
     any (divides n) [modExp base (2 ^ r * d) n + 1 | r <- [0 .. s - 1]]

isPrimeU :: Integer -> Bool
isPrimeU = unsafePerformIO . isPrime

--- FACTORIZATION: RHO-POLLARD

factor :: Integer -> Integer -> Integer
factor c n = factor' 2 2 1
  where
    f x = mod (x * x + c) n
    factor' x y 1 = factor' x' y' (gcd (x' - y') n)
      where
        (x', y') = (f x, f $ f y)
    factor' _ _ d =
      if d == n
        then factor (c + 1) n
        else d

factors :: Integer -> [Integer]
factors n = sort $ fs n
  where
    fs x
      | x < 0 = (-1) : fs ((-1) * x)
      | x == 1 = []
      | even x = 2 : fs (div x 2)
      | isPrimeU x = [x]
      | otherwise = f : fs (div x f)
      where
        f = factor 1 x

sortUniq :: Ord a => [a] -> [a]
sortUniq = sort . nub

--- MOEBIUS FUNCTION

moebius :: Integer -> Integer
moebius n
  | sortUniq facs == facs =
    if even $ length facs
      then 1
      else -1
  | otherwise = 0
  where
    facs = factors n

--- EULER FUNCTION

euler :: Integer -> Integer
euler n =
  let pfactors = sortUniq $ factors n
      ratio = Data.List.foldl (\acc x -> acc * (1 - 1 % x)) (n % 1) $ pfactors
  in numerator ratio `div` denominator ratio

--- JACOBI SYMBOL

jacobi :: Integer -> Integer -> Maybe Integer
jacobi a0 m0
  | even m0 = Nothing
  | otherwise = Just $ jacobi' a0 m0
  where
    jacobi' a m
      | a == 0 = a
      | a == 1 = a
      | a == 2 =
        if (m `mod` 8) `elem` [3, 5]
          then -1
          else 1
      | even a = jacobi' 2 m * jacobi' (a `div` 2) m
      | a >= m = jacobi' (a `mod` m) m
      | otherwise =
        let v = jacobi' m a
        in if (a `mod` 4 == 3) && (m `mod` 4 == 3)
             then -v
             else v

jacobi_ :: Integer -> Integer -> Integer
jacobi_ a m = unMaybe $ jacobi a m

--- LEGENDRE SYMBOL

legendre :: Integer -> Integer -> Maybe Integer
legendre a m
  | isPrimeU m = jacobi a m
  | otherwise = Nothing

legendre_ :: Integer -> Integer -> Integer
legendre_ a m = unMaybe $ legendre a m


--- UTILITY

randPrime :: CryptoRandomGen g =>
                    g -> Int ->
                    (Integer, g)
randPrime g len =
  let (h_t, g')        = randomBS g 2
      [startH, startT] = BS.unpack h_t
      (startMids, g'') = randomBS g' (len - 2)
      bstr             = BS.concat [BS.singleton (startH .|. 0xc0),
                                      startMids, BS.singleton (startT .|. 1)]
    in findNextPrime g'' (os2ip bstr)

randomBS :: CryptoRandomGen g => g -> Int -> (ByteString, g)
randomBS g n =
  case genBytes n g of
    Left _ -> error "Failed to generate randomness"
    Right (bs, g') -> (BS.fromChunks [bs], g')

findNextPrime :: CryptoRandomGen g =>
                 g -> Integer ->
                 (Integer, g)
findNextPrime g n
  | even n             = findNextPrime g (n + 1)
  | n `mod` 65537 == 1 = findNextPrime g (n + 2)
  | otherwise          = case isPrimeU n of
                           True -> (n, g)
                           False -> findNextPrime g (n + 2)

i2osp :: Integral a => a -> Int -> ByteString
i2osp x len | isTooLarge = error "Int too large"
            | otherwise  = (padding `BS.append` digits)
 where
  isTooLarge  = (fromIntegral x :: Integer) >=
                (256 ^ (fromIntegral len :: Integer))
  padding     = BS.replicate (fromIntegral len - BS.length digits) 0
  digits      = BS.reverse (BS.unfoldr digitize x)
  digitize 0  = Nothing
  digitize v  = let (q, r) = divMod v 256
                in Just (fromIntegral r, q)

os2ip :: ByteString -> Integer
os2ip = BS.foldl (\ a b -> (256 * a) + (fromIntegral b)) 0

modExp :: Integer -> Integer -> Integer -> Integer
modExp _ 0 _ = 1
modExp b e m = t * modExp ((b * b) `mod` m) (shiftR e 1) m `mod` m
  where
    t =
      if testBit e 0
        then b `mod` m
        else 1

extEuclid :: Integer -> Integer -> (Integer, Integer, Integer)
extEuclid a b
  | b == 0 = (a, 1, 0)
  | otherwise = (d, t, s - q * t)
  where
    (q, r) = a `divMod` b
    (d, s, t) = extEuclid b r


modMulInv :: Integer -> Integer -> Integer
modMulInv a m
  | gcdV /= 1    = undefined
  | otherwise   = x `mod` m
  where
    (gcdV, x, _) = extEuclid a m

divides :: Integer -> Integer -> Bool
divides a b = mod b a == 0

extractPowersOf :: Integer -> Integer -> (Integer, Integer)
extractPowersOf a b =
  head . dropWhile (divides a . snd) . iterate ((+ 1) *** (`div` a)) $ (0, b)

unMaybe :: Maybe a -> a
unMaybe m =
  case m of
    Just x -> x
    Nothing -> undefined

