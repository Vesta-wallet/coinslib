import 'dart:typed_data';
import 'package:bip32/src/utils/ecurve.dart' show isPoint;
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';

const int max_multisig_pubkeys = 20;

/// Creates a multisig redeem script using CHECKMULTISIG for the [pubkeys]
/// requiring [threshold] signatures. If [threshold] is not given, then all
/// public keys are required.
Uint8List createMultisigScript({
  required List<Uint8List> pubkeys, int threshold = -1
}) {

  if (threshold < 0) threshold = pubkeys.length;

  if (threshold == 0 || threshold > pubkeys.length) {
    throw ArgumentError(
      'The threshold must be from 1 up-to the number of public keys'
    );
  }

  if (pubkeys.length > max_multisig_pubkeys || pubkeys.isEmpty) {
    throw ArgumentError(
      'Must have 1-$max_multisig_pubkeys public keys in a multisig script'
    );
  }

  if (pubkeys.any((pk) => !isPoint(pk))) {
    throw ArgumentError('At least one public key argument is not valid');
  }

  return bscript.compile([
    bscript.pushUint8(threshold),
    ...pubkeys,
    bscript.pushUint8(pubkeys.length),
    OPS['OP_CHECKMULTISIG']
  ]);

}

