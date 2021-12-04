import 'dart:typed_data';
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';

/// Takes the hash160 ([scriptHash]) of a P2SH redeemScript and returns the
/// output script (scriptPubKey)
Uint8List createP2shOutputScript(Uint8List scriptHash) {

  if (scriptHash.length != 20)
    throw new ArgumentError('Invalid script hash length');

  return bscript.compile([OPS['OP_HASH160'], scriptHash, OPS['OP_EQUAL']]);

}

