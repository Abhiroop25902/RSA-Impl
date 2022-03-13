BigInt str2BigInt(String s) {
  var binary = s.codeUnits.map((e) {
    var res = e.toRadixString(2);
    // if by any reason the bit representation is not of length 7 (7 bit ascii), prepend '0'
    if (res.length < 7) { 
      res = '0' * (7 - res.length) + res;
    } else if (res.length > 7) {
      throw Exception('Error: ASCII Bit value has len >7');
    }
    return res;
  }).toList();
  return BigInt.parse(binary.join(''), radix: 2);
}


/// NOTE: 7 because of ASCII 7 bit representation
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
