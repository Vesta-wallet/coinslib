import 'dart:typed_data';
import 'package:coinslib/coinslib.dart';
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';
import "../crypto.dart" show hash160;
import 'package:bs58check/bs58check.dart' as bs58check;

class P2SH {
  Uint8List scriptHash;

  P2SH.fromScriptHash(Uint8List hash) : scriptHash = hash {
    if (scriptHash.length != 20) {
      throw ArgumentError('Invalid P2SH script hash length');
    }
  }

  P2SH.fromScriptBytes(Uint8List bytes) : this.fromScriptHash(hash160(bytes));
  P2SH.fromMultisig(MultisigScript script)
      : this.fromScriptBytes(script.scriptBytes);
  P2SH.fromP2WPKH(P2WPKH p2wpkh) : this.fromScriptBytes(p2wpkh.outputScript);

  /// Returns the outputScript (scriptPubKey)
  Uint8List get outputScript =>
      bscript.compile([ops["OP_HASH160"], scriptHash, ops["OP_EQUAL"]]);

  /// Returns the base58 address for a given network
  String address(NetworkType network) {
    final payload = Uint8List(21);
    payload.buffer.asByteData().setUint8(0, network.scriptHash);
    payload.setRange(1, payload.length, scriptHash);
    return bs58check.encode(payload);
  }
}
