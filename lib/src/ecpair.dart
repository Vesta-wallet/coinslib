import 'dart:typed_data';
import 'dart:math';
import './utils/ecurve.dart' as ecc;
import './utils/wif.dart' as wif;
import 'models/networks.dart';

/// Despite the name, can refer to only a public key
class ECPair {
  Uint8List? _d;
  Uint8List? _q;
  NetworkType network;
  bool compressed;

  ECPair(this._d, this._q, {NetworkType? network, bool? compressed})
      : network = network ?? bitcoin,
        compressed = compressed ?? true;

  Uint8List? get publicKey {
    _q ??= ecc.pointFromScalar(_d!, compressed);
    return _q;
  }

  Uint8List? get privateKey => _d;

  String toWIF() {
    if (privateKey == null) {
      throw ArgumentError('Missing private key');
    }
    return wif.encode(
      wif.WIF(
        version: network.wif,
        privateKey: privateKey!,
        compressed: compressed,
      ),
    );
  }

  Uint8List sign(Uint8List hash) {
    return ecc.sign(hash, privateKey!);
  }

  Uint8List signRecoverable(Uint8List hash) {
    return ecc.signRecoverable(hash, privateKey!);
  }

  bool verify(Uint8List hash, Uint8List signature) {
    return ecc.verify(hash, publicKey!, signature);
  }

  factory ECPair.fromWIF(String w, {NetworkType? network}) {
    wif.WIF decoded = wif.decode(w);
    final version = decoded.version;
    // TODO support multi networks
    NetworkType nw;
    if (network != null) {
      nw = network;
      if (nw.wif != version) throw ArgumentError('Invalid network version');
    } else {
      if (version == bitcoin.wif) {
        nw = bitcoin;
      } else if (version == testnet.wif) {
        nw = testnet;
      } else {
        throw ArgumentError('Unknown network version');
      }
    }
    return ECPair.fromPrivateKey(
      decoded.privateKey,
      compressed: decoded.compressed,
      network: nw,
    );
  }

  factory ECPair.fromPublicKey(
    Uint8List publicKey, {
    NetworkType? network,
    bool? compressed,
  }) {
    if (!ecc.isPoint(publicKey)) {
      throw ArgumentError('Point is not on the curve');
    }
    return ECPair(null, publicKey, network: network, compressed: compressed);
  }

  factory ECPair.fromPrivateKey(
    Uint8List privateKey, {
    NetworkType? network,
    bool? compressed,
  }) {
    if (privateKey.length != 32) {
      throw ArgumentError(
        'Expected property privateKey of type Buffer(Length: 32)',
      );
    }
    if (!ecc.isPrivate(privateKey)) {
      throw ArgumentError('Private key not in range [1, n)');
    }
    return ECPair(privateKey, null, network: network, compressed: compressed);
  }

  factory ECPair.makeRandom({
    NetworkType? network,
    bool? compressed,
    Function? rng,
  }) {
    final rfunc = rng ?? _randomBytes;
    Uint8List d;
    do {
      d = rfunc(32);
      if (d.length != 32) throw ArgumentError('Expected Buffer(Length: 32)');
    } while (!ecc.isPrivate(d));
    return ECPair.fromPrivateKey(d, network: network, compressed: compressed);
  }

  /// Recover public key from a hash and signature with a recid included
  factory ECPair.recover({
    required Uint8List hash,
    required Uint8List signature,
  }) {
    return ECPair.fromPublicKey(ecc.recover(hash, signature));
  }
}

const int _sizeByte = 256;

Uint8List _randomBytes(int size) {
  final rng = Random.secure();
  final bytes = Uint8List(size);
  for (var i = 0; i < size; i++) {
    bytes[i] = rng.nextInt(_sizeByte);
  }
  return bytes;
}
