import 'dart:io';

import './rsa/utils.dart' as utils
    show generateLargePrime, generateKeys, str2BigInt, bigIntToStr;
import 'rsa/decrypt.dart' as decrypt show decryptRsa;
import 'rsa/encrypt.dart' as encrypt show encryptRsa;

const keySize = 256;
late BigInt e;
late BigInt d;
late BigInt n;

void generateNewKeys({bool verbose = true}) {
  var p = utils.generateLargePrime(keySize);
  var q = utils.generateLargePrime(keySize);
  if (verbose) {
    print('');
    print("Generating primes...");
    print('p: $p');
    print('q: $q');
  }
  var res = utils.generateKeys(p, q);
  e = res[0];
  d = res[1];
  n = res[2];
  if (verbose) {
    print("");
    print('Public key: ');
    print('e: $e');
    print('n: $n');
    print('Private key: ');
    print('d: $d');
    print('n: $n');
    print("");
  }
}

void encryptMessage() {
  // stdout.write('Public key (e): ');
  // var e = BigInt.parse(stdin.readLineSync()!);
  // stdout.write('Public key (n): ');
  // var n = BigInt.parse(stdin.readLineSync()!);
  stdout.write('Message: ');
  var m = utils.str2BigInt(stdin.readLineSync()!);
  var c = encrypt.encryptRsa(m, e, n);
  print("Encrypted message: $c");
  print("");
}

void decryptMessage() {
  // stdout.write('Private key (d): ');
  // var d = BigInt.parse(stdin.readLineSync()!);
  // stdout.write('Private key (n): ');
  // var n = BigInt.parse(stdin.readLineSync()!);
  stdout.write('Ciphertext: ');
  var c = BigInt.parse(stdin.readLineSync()!);
  var m = utils.bigIntToStr(decrypt.decryptRsa(c, d, n));
  print("Decrypted message: $m");
  print("");
}

void main(List<String> arguments) {
  generateNewKeys(verbose: false);
  while (true) {
    print("RSA Encryption/Decryption");
    print("=========================");
    print("");
    print("Choose an option:");
    print("1. Generate new keys");
    print("2. Encrypt a message");
    print("3. Decrypt a message");
    print("4. Exit");
    print("");
    var option = int.parse(stdin.readLineSync()!);
    if (option == 1) {
      generateNewKeys();
    } else if (option == 2) {
      encryptMessage();
    } else if (option == 3) {
      decryptMessage();
    } else {
      print("\nby Abhiroop Mukherjee (510519109)");
      break;
    }
  }
}
