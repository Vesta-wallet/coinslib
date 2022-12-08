import 'dart:typed_data';
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';
import '../crypto.dart' show hashSha256;
import './multisig.dart';
import '../models/networks.dart';
import 'package:coinslib/bech32/bech32.dart';

class P2WSH {

  Uint8List scriptHash;

  P2WSH.fromScriptHash(Uint8List hash) : scriptHash = hash {
    if (scriptHash.length != 32) {
      throw ArgumentError('Invalid script hash length');
    }
  }
  P2WSH.fromScriptBytes(Uint8List bytes)
    : this.fromScriptHash(hashSha256(bytes));
  P2WSH.fromMultisig(MultisigScript script) : this.fromScriptBytes(script.scriptBytes);

  /// Returns the outputScript (scriptPubKey)
  Uint8List get outputScript => bscript.compile([ops['OP_0'], scriptHash]);

  /// Returns the bech32 address for a given network
  String address(NetworkType network)
    => segwit.encode(Segwit(network.bech32!, 0, scriptHash));

}

