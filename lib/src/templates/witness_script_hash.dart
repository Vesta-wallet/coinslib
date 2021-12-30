import 'dart:typed_data';
import 'package:coinslib/src/payments/multisig.dart';

import '../utils/script.dart' as bscript;

/// Checks the input witness is a multisig P2WSH. All P2WSH are expected to be
/// multisig.
bool inputCheck(List<Uint8List> witness) {

  if (witness.isEmpty) return false;

  // Check that the first argument is a single 0 byte
  if (witness.first.length != 1 || witness.first[0] != 0) return false;

  // Check witnessScript
  try {
    final multisig = MultisigScript.fromScriptBytes(witness.last);
    // Check the number of witness data should include signatures, witness
    // script and an extra unused data at the start
    if (witness.length != 2 + multisig.threshold) return false;
  } on ArgumentError {
    return false;
  }

  // Check that we have signatures after the initial ignored data
  for (final sig in witness.getRange(1, witness.length-1)) {
    if (!bscript.isCanonicalScriptSignature(sig)) return false;
  }

  return true;

}

