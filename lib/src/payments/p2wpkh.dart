import 'dart:typed_data';
import 'package:coinslib/bech32/bech32.dart';
import '../crypto.dart';
import '../models/networks.dart';
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';

class P2WPKH {
  Uint8List pubKeyHash;

  P2WPKH.fromPublicKeyHash(Uint8List hash) : pubKeyHash = hash {
    if (hash.length != 20) {
      throw ArgumentError('Invalid P2WPKH public key hash length');
    }
  }

  P2WPKH.fromPublicKey(Uint8List publicKey)
      : this.fromPublicKeyHash(hash160(publicKey));

  Uint8List get outputScript => bscript.compile(
        [ops["OP_0"], pubKeyHash],
      );

  /// Returns the bech32 address for a given network
  String address(NetworkType network) =>
      segwit.encode(Segwit(network.bech32!, 0, pubKeyHash));
}
