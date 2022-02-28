// RSA Encryption
BigInt encryptRsa(BigInt plainText, BigInt e, BigInt n) {
  return plainText.modPow(e, n);
}
