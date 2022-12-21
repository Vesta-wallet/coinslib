import 'dart:typed_data';
import 'package:bs58check/bs58check.dart' as bs58check;
import '../crypto.dart';
import '../models/networks.dart';
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';

class P2PKH {
  Uint8List pubKeyHash;

  P2PKH.fromPublicKeyHash(Uint8List hash) : pubKeyHash = hash {
    if (hash.length != 20) {
      throw ArgumentError('Invalid P2PKH public key hash length');
    }
  }

  P2PKH.fromPublicKey(Uint8List publicKey)
      : this.fromPublicKeyHash(hash160(publicKey));

  Uint8List get outputScript => bscript.compile(
        [
          ops["OP_DUP"],
          ops["OP_HASH160"],
          pubKeyHash,
          ops["OP_EQUALVERIFY"],
          ops["OP_CHECKSIG"]
        ],
      );

  /// Returns the base58 address for a given network
  String address(NetworkType network) {
    final payload = Uint8List(21);
    payload.buffer.asByteData().setUint8(0, network.pubKeyHash);
    payload.setRange(1, payload.length, pubKeyHash);
    return bs58check.encode(payload);
  }
}
