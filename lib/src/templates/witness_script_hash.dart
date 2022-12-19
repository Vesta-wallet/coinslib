import 'dart:typed_data';
import 'package:coinslib/src/payments/multisig.dart';

import '../utils/script.dart' as bscript;

/// Checks the input witness is a multisig P2WSH. All P2WSH are expected to be
/// multisig. It checks if there are 0 to threshold signatures and therefore allows
/// incomplete signatures
bool inputCheck(List<Uint8List> witness) {
  if (witness.length < 2) return false;

  // Check that the first argument is an empty array (BIP 147)
  if (witness.first.isNotEmpty) return false;

  // Check witnessScript
  try {
    final multisig = MultisigScript.fromScriptBytes(witness.last);
    // Check that the witness data does not exceed the threshold number of
    // signatures plus the ignored data and script
    if (witness.length > 2 + multisig.threshold) return false;
  } on ArgumentError {
    return false;
  }

  // Check that signatures after the initial ignored data are valid
  for (final sig in witness.getRange(1, witness.length - 1)) {
    if (!bscript.isCanonicalScriptSignature(sig)) return false;
  }

  return true;
}
