/// RSA decryption
BigInt decryptRsa(BigInt cipherText, BigInt d, BigInt n) {
  return cipherText.modPow(d, n);
}
