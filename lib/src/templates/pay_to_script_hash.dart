import 'dart:typed_data';
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';
import 'package:coinslib/src/payments/multisig.dart';

// This is similar to the inputCheck for P2WSH and a candidate for abstraction.
/// Only allows multisig P2SH at the moment
bool inputCheck(List<dynamic> chunks) {

  if (chunks.length < 2) return false;

  // Check that the first item is 0 which is necessary for CHECKMULTISIG
  if (chunks[0] != 0) return false;

  // Last push needs to be the redeemScript
  if (chunks.last is! Uint8List) return false;

  // Check redeemScript is multisig
  try {
    final multisig = MultisigScript.fromScriptBytes(chunks.last);
    // Can only have upto threshold sigs plus OP_0 and redeemScript
    if (chunks.length > 2 + multisig.threshold) return false;
  } on ArgumentError {
    return false;
  }

  // Check signatures
  for (final sig in chunks.getRange(1, chunks.length - 1)) {
    if (!bscript.isCanonicalScriptSignature(sig)) return false;
  }

  return true;

}

bool outputCheck(Uint8List script) {
  final buffer = bscript.compile(script);
  return buffer.length == 23 &&
      buffer[0] == ops['OP_HASH160'] &&
      buffer[1] == 0x14 &&
      buffer[22] == ops['OP_EQUAL'];
}
