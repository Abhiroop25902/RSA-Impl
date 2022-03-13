import 'dart:io';

import './rsa/utils.dart' as utils
    show generateLargePrime, generateKeys, str2BigInt, bigIntToStr, keySize;
import 'rsa/decrypt.dart' as decrypt show decryptRsa;
import 'rsa/encrypt.dart' as encrypt show encryptRsa;

late BigInt e;
late BigInt d;
late BigInt n;

void generateNewKeys() {
  var p = utils.generateLargePrime(utils.keySize);
  var q = utils.generateLargePrime(utils.keySize);

  // print('');
  // print('Generating primes...');
  // print('p: $p');
  // print('q: $q');

  var res = utils.generateKeys(p, q);
  e = res[0];
  d = res[1];
  n = res[2];
  print('Keys Generated!!');
  showPublicKeys();
}

void showPublicKeys() {
  print('');
  print('Public key: ');
  print('e: $e');
  print('n: $n');
  // print('Private key: ');
  // print('d: $d');
  // print('n: $n');
}

void encryptMessage() {
  stdout.write('Message: ');
  var m = utils.str2BigInt(stdin.readLineSync()!);
  print('Enter Public Key of Recipient');
  stdout.write('Enter e: ');
  var recpE = BigInt.parse(stdin.readLineSync()!);
  stdout.write('Enter n: ');
  var recpN = BigInt.parse(stdin.readLineSync()!);
  print('e: $e');
  var c = encrypt.encryptRsa(m, recpE, recpN);
  print('Encrypted message: $c');
}

void decryptMessage() {
  stdout.write('Ciphertext: ');
  var c = BigInt.parse(stdin.readLineSync()!);
  var m = utils.bigIntToStr(decrypt.decryptRsa(c, d, n));
  print('Decrypted message: $m');
}

void main(List<String> arguments) {
  generateNewKeys();
  while (true) {
    print('');
    print('┌──────────────────────────────────────────────────────────────┐');
    print('│  RSA Encryption/Decryption by Abhiroop Mukherjee (510519109) │');
    print('└──────────────────────────────────────────────────────────────┘');
    print('Choose an option:');
    print('1. Generate new keys');
    print('2. Show public keys');
    print('3. Encrypt a message');
    print('4. Decrypt a message');
    print('5. Exit');
    stdout.write('Option: ');
    var option = int.parse(stdin.readLineSync()!);

    if (option == 1) {
      generateNewKeys();
    } else if (option == 2) {
      showPublicKeys();
    } else if (option == 3) {
      encryptMessage();
    } else if (option == 4) {
      decryptMessage();
    } else {
      print('Byeeeee!');
      break;
    }
  }
}
