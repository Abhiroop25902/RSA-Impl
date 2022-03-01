import 'dart:math';

import 'package:ninja_prime/ninja_prime.dart';

const int keySize = 256;

/// Extended Euclidean algorithm
/// Returns [gcd, x, y] where gcd = gcd(a, b),
///        x = ay + bx, y = by - a * x
List<BigInt> egcd(BigInt a, BigInt b) {
  if (a == BigInt.zero) {
    return [b, BigInt.zero, BigInt.one];
  }

  var res = egcd(b % a, a);
  var g = res[0];
  var y = res[1];
  var x = res[2];

  return [g, x - (b ~/ a) * y, y];
}

/// Modular inverse, Raises: Exception: if [a] is not coprime to [m]
BigInt modinv(BigInt a, BigInt m) {
  var res = egcd(a, m);
  var g = res[0];
  var x = res[1];
  // var y = res[2];

  if (g != BigInt.one) {
    throw Exception('modular inverse does not exist');
  }
  return x % m;
}

/// Generate RSA Keys
List<BigInt> generateKeys(BigInt p, BigInt q) {
  BigInt n = p * q;
  BigInt phi = (p - BigInt.one) * (q - BigInt.one);
  BigInt e = BigInt.from(65537);
  var d = e.modInverse(phi);
  return [e, d, n];
}

BigInt str2BigInt(String s) {
  // for some reason e.toRadixString was converting ' ' to 100000 (six bits)
  // rather than 0100000 so added a conditional
  var binary = s.codeUnits.map((e) {
    var res = e.toRadixString(2);
    if (res.length < 7) {
      res = '0' * (7 - res.length) + res;
    } else if (res.length > 7) {
      throw Exception('Error: ASCII Bit value has len >7');
    }
    return res;
  }).toList();
  return BigInt.parse(binary.join(''), radix: 2);
}

List<String> _splitBy7(String binary) {
  int strSize = binary.length;
  int steps = strSize ~/ 7;
  List<String> ans = [];
  for (int i = 0; i < steps; i++) {
    ans.add(binary.substring(i * 7, (i + 1) * 7));
  }
  return ans;
}

String bigIntToStr(BigInt s) {
  String binaryString = s.toRadixString(2);
  var binaryCharacters = _splitBy7(binaryString);
  return binaryCharacters
      .map((e) => String.fromCharCode(int.parse(e, radix: 2)))
      .join();
}

/// Rabin–Miller primality test is a probabilistic primality test: an
///algorithm which determines whether a given number is likely to be prime
bool rabinMiller(BigInt n) {
  var s = n - BigInt.one;
  var t = BigInt.zero;

  while (s & BigInt.one == BigInt.zero) {
    s = s ~/ BigInt.two;
    t = t + BigInt.one;
  }

  var k = BigInt.zero;

  while (k < BigInt.from(keySize)) {
    var a = randomBigInt(keySize, random: Random.secure()) % (n - BigInt.two) +
        BigInt.two;
    var v = a.modPow(s, n);

    if (v != BigInt.one) {
      var i = BigInt.zero;
      while (v != n - BigInt.one) {
        if (i == t - BigInt.one) {
          return false;
        } else {
          i = i + BigInt.one;
          v = v.modPow(BigInt.two, n);
        }
      }
    }
    k = k + BigInt.two;
  }
  return true;
}

/// Standard Prime Check
/// lowPrimes is all primes (sans 2, which is covered by the bitwise and
/// operator) under 1000. taking n modulo each lowPrime allows us to remove a
/// huge chunk of composite numbers from our potential pool without resorting to
/// Rabin-Miller
bool isPrime(BigInt n) {
  var lowPrimes = [
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
    137,
    139,
    149,
    151,
    157,
    163,
    167,
    173,
    179,
    181,
    191,
    193,
    197,
    199,
    211,
    223,
    227,
    229,
    233,
    239,
    241,
    251,
    257,
    263,
    269,
    271,
    277,
    281,
    283,
    293,
    307,
    311,
    313,
    317,
    331,
    337,
    347,
    349,
    353,
    359,
    367,
    373,
    379,
    383,
    389,
    397,
    401,
    409,
    419,
    421,
    431,
    433,
    439,
    443,
    449,
    457,
    461,
    463,
    467,
    479,
    487,
    491,
    499,
    503,
    509,
    521,
    523,
    541,
    547,
    557,
    563,
    569,
    571,
    577,
    587,
    593,
    599,
    601,
    607,
    613,
    617,
    619,
    631,
    641,
    643,
    647,
    653,
    659,
    661,
    673,
    677,
    683,
    691,
    701,
    709,
    719,
    727,
    733,
    739,
    743,
    751,
    757,
    761,
    769,
    773,
    787,
    797,
    809,
    811,
    821,
    823,
    827,
    829,
    839,
    853,
    857,
    859,
    863,
    877,
    881,
    883,
    887,
    907,
    911,
    919,
    929,
    937,
    941,
    947,
    953,
    967,
    971,
    977,
    983,
    991,
    997
  ].map((e) => BigInt.from(e));

  if (n >= BigInt.from(3)) {
    if (n & BigInt.one != BigInt.zero) {
      for (var p in lowPrimes) {
        if (n == p) return true;
        if (n % p == BigInt.zero) return false;
      }
      return rabinMiller(n);
    }
  }
  return false;
}

///Generate large prime number of length k
BigInt generateLargePrime(int k) {
  var r = (100 * (log(k) / log(2) + 1)).floor();
  var rCopy = r;

  while (r > 0) {
    var n = randomBigInt(k, random: Random.secure()) %
            (BigInt.two.pow(k) - BigInt.two.pow(k - 1)) +
        BigInt.two.pow(k - 1);
    BigInt.two.pow(k - 1);
    r--;

    if (isPrime(n)) return n;
  }
  throw Exception('failure after $rCopy tries');
}
