import 'dart:io';
import 'utils.dart' as utils;
import 'rsa.dart' show Rsa;

void encryptMessage() {
  stdout.write('Message: ');
  var m = utils.str2BigInt(stdin.readLineSync()!);
  print('Enter Public Key of Recipient');
  stdout.write('Enter e: ');
  var recpE = BigInt.parse(stdin.readLineSync()!);
  stdout.write('Enter n: ');
  var recpN = BigInt.parse(stdin.readLineSync()!);
  var c = Rsa.encryptRsa(m, recpE, recpN);
  print('Encrypted message: $c');
}

void decryptMessage(Rsa rsa) {
  stdout.write('Ciphertext: ');
  var c = BigInt.parse(stdin.readLineSync()!);
  rsa.decryptRsa(c);
  var m = utils.bigIntToStr(rsa.decryptRsa(c));
  print('Decrypted message: $m');
}

void main(List<String> arguments) {
  Rsa rsa = Rsa();
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
      rsa = Rsa();
    } else if (option == 2) {
      print(rsa);
    } else if (option == 3) {
      encryptMessage();
    } else if (option == 4) {
      decryptMessage(rsa);
    } else {
      print('Byeeeee!');
      break;
    }
  }
}
