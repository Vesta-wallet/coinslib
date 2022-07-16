import 'dart:typed_data';
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';

/// Takes the sha256 hash ([scriptHash]) of a witnessScript and returns the
/// output script (scriptPubKey)
Uint8List createP2wshOutputScript(Uint8List scriptHash) {
  if (scriptHash.length != 32) {
    throw ArgumentError('Invalid script hash length');
  }

  return bscript.compile([ops['OP_0'], scriptHash]);
}
