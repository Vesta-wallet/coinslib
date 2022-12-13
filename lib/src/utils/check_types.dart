import 'dart:typed_data';
import 'dart:math';

// TODO: This is not network specific
final satoshiMax = BigInt.from(21 * 1e14);

bool isSatoshi(BigInt value) {
  return !value.isNegative && value <= satoshiMax;
}

bool isUint(int value, int bit) {
  return (value >= 0 && value <= pow(2, bit) - 1);
}

bool isHash160bit(Uint8List value) {
  return value.length == 20;
}

bool isHash256bit(Uint8List value) {
  return value.length == 32;
}
