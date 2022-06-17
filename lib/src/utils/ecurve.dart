import 'dart:typed_data';
import 'package:hex/hex.dart';
import "package:pointycastle/ecc/curves/secp256k1.dart";
import "package:pointycastle/api.dart" show PrivateKeyParameter, PublicKeyParameter;
import 'package:pointycastle/ecc/api.dart' show ECPrivateKey, ECPublicKey, ECSignature, ECPoint;
import "package:pointycastle/signers/ecdsa_signer.dart";
import 'package:pointycastle/macs/hmac.dart';
import "package:pointycastle/digests/blake2b.dart";
import 'package:pointycastle/src/utils.dart';
import 'package:collection/collection.dart';

final ZERO32 = Uint8List.fromList(List.generate(32, (index) => 0));
final EC_GROUP_ORDER = HEX.decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
final EC_P = HEX.decode("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
final secp256k1 = ECCurve_secp256k1();
final n = secp256k1.n;
final G = secp256k1.G;
BigInt nDiv2 = n >> 1;
const THROW_BAD_PRIVATE = 'Expected Private';
const THROW_BAD_POINT = 'Expected Point';
const THROW_BAD_TWEAK = 'Expected Tweak';
const THROW_BAD_HASH = 'Expected Hash';
const THROW_BAD_SIGNATURE = 'Expected Signature';

bool isPrivate(Uint8List x) {
  if (!isScalar(x)) return false;
  return _compare(x, ZERO32) > 0 && // > 0
      _compare(x, EC_GROUP_ORDER as Uint8List) < 0; // < G
}

bool isPoint(Uint8List p) {
  if (p.length < 33) {
    return false;
  }
  var t = p[0];
  var x = p.sublist(1, 33);

  if (_compare(x, ZERO32) == 0) {
    return false;
  }
  if (_compare(x, EC_P as Uint8List) == 1) {
    return false;
  }
  try {
    decodeFrom(p);
  } catch (err) {
    return false;
  }
  if ((t == 0x02 || t == 0x03) && p.length == 33) {
    return true;
  }
  var y = p.sublist(33);
  if (_compare(y, ZERO32) == 0) {
    return false;
  }
  if (_compare(y, EC_P as Uint8List) == 1) {
    return false;
  }
  if (t == 0x04 && p.length == 65) {
    return true;
  }
  return false;
}

bool isScalar(Uint8List x) {
  return x.length == 32;
}

bool isOrderScalar(x) {
  if (!isScalar(x)) return false;
  return _compare(x, EC_GROUP_ORDER as Uint8List) < 0; // < G
}

bool isSignature(Uint8List value) {
  Uint8List r = value.sublist(0, 32);
  Uint8List s = value.sublist(32, 64);

  return value.length == 64 && _compare(r, EC_GROUP_ORDER as Uint8List) < 0 && _compare(s, EC_GROUP_ORDER as Uint8List) < 0;
}

bool _isPointCompressed(Uint8List p) {
  return p[0] != 0x04;
}

bool assumeCompression(bool? value, Uint8List? pubkey) {
  if (value == null && pubkey != null) return _isPointCompressed(pubkey);
  if (value == null) return true;
  return value;
}

Uint8List? pointFromScalar(Uint8List d, bool _compressed) {
  if (!isPrivate(d)) throw ArgumentError(THROW_BAD_PRIVATE);
  BigInt dd = fromBuffer(d);
  ECPoint pp = (G * dd) as ECPoint;
  if (pp.isInfinity) return null;
  return getEncoded(pp, _compressed);
}

Uint8List? pointAddScalar(Uint8List p, Uint8List tweak, bool _compressed) {
  if (!isPoint(p)) throw ArgumentError(THROW_BAD_POINT);
  if (!isOrderScalar(tweak)) throw ArgumentError(THROW_BAD_TWEAK);
  bool compressed = assumeCompression(_compressed, p);
  ECPoint? pp = decodeFrom(p);
  if (_compare(tweak, ZERO32) == 0) return getEncoded(pp, compressed);
  BigInt tt = fromBuffer(tweak);
  ECPoint qq = (G * tt) as ECPoint;
  ECPoint uu = (pp! + qq) as ECPoint;
  if (uu.isInfinity) return null;
  return getEncoded(uu, compressed);
}

Uint8List? privateAdd(Uint8List d, Uint8List tweak) {
  if (!isPrivate(d)) throw ArgumentError(THROW_BAD_PRIVATE);
  if (!isOrderScalar(tweak)) throw ArgumentError(THROW_BAD_TWEAK);
  BigInt dd = fromBuffer(d);
  BigInt tt = fromBuffer(tweak);
  Uint8List dt = toBuffer((dd + tt) % n);

  if (dt.length < 32) {
    Uint8List padLeadingZero = Uint8List(32 - dt.length);
    dt = Uint8List.fromList(padLeadingZero + dt);
  }

  if (!isPrivate(dt)) return null;
  return dt;
}

Uint8List sign(Uint8List hash, Uint8List x) {

  if (!isScalar(hash)) throw ArgumentError(THROW_BAD_HASH);
  if (!isPrivate(x)) throw ArgumentError(THROW_BAD_PRIVATE);

  ECSignature sig = deterministicSignature(hash, x);
  final bb = BytesBuilder();
  bb.add(_encodeBigInt(sig.r));
  final s = sig.s.compareTo(nDiv2) > 0 ? n - sig.s : sig.s;
  bb.add(_encodeBigInt(s));
  return bb.toBytes();

}

Uint8List signRecoverable(Uint8List hash, Uint8List privKey) {

  Uint8List sig = sign(hash, privKey);
  Uint8List pubKey = pointFromScalar(privKey, true)!;

  // Need to add "recid" byte to specify how to derive the public key from the
  // signature, thus making it recoverable.
  // As we do not have the R point y coordinate, try recovery with recids of
  // 0 and 1 and choose the one that corresponds to the public key
  for (int recid = 0; recid < 2; recid++) {
    final fullSig = Uint8List.fromList([31 + recid] + sig);
    if (ListEquality().equals(recover(fullSig, hash), pubKey))
      return fullSig;
  }

  throw ArgumentError(
    "Could not generate a recoverable signature from private key"
  );

}

/// This function is used to check the recids for recoverable signatures. It
/// could be used to recover public keys to verify signatures too but it should
/// probably do more checks first.
Uint8List recover(Uint8List sig, Uint8List hash) {

  if (sig.length != 65) {
    throw ArgumentError(
      "Can only recover from signatures with 65 bytes including recid"
    );
  }

  final recid = (sig[0] - 27) & 3;
  if (recid > 1) {
    throw ArgumentError("Can only recover from 0 or 1 recids");
  }

  if (!isSignature(sig.sublist(1))) throw ArgumentError(THROW_BAD_SIGNATURE);

  final r = fromBuffer(sig.sublist(1, 33));
  final s = fromBuffer(sig.sublist(33, 65));

  // Obtain R point and e scalar
  final R = secp256k1.curve.decompressPoint(recid, r);
  final e = _calculateE(hash);

  // Invert r scalar
  final invr = r.modInverse(secp256k1.n);

  // Calculate candidate Q
  final sR = R*s;
  final eG = G*e;

  final Q = (sR! - eG!)!*invr;

  return Q!.getEncoded();

}

// Adapted from pointycastle
BigInt _calculateE(Uint8List message) {

  final log2n = secp256k1.n.bitLength;
  final messageBitLength = message.length * 8;
  final decoded = decodeBigIntWithSign(1, message);

  return log2n >= messageBitLength
    ? decoded
    : decoded >> (messageBitLength - log2n);

}

bool verify(Uint8List hash, Uint8List q, Uint8List signature) {
  if (!isScalar(hash)) throw ArgumentError(THROW_BAD_HASH);
  if (!isPoint(q)) throw ArgumentError(THROW_BAD_POINT);
  // 1.4.1 Enforce r and s are both integers in the interval [1, n − 1] (1, isSignature enforces '< n - 1')
  if (!isSignature(signature)) throw ArgumentError(THROW_BAD_SIGNATURE);

  ECPoint? Q = decodeFrom(q);
  BigInt r = fromBuffer(signature.sublist(0, 32));
  BigInt s = fromBuffer(signature.sublist(32, 64));

  final signer = ECDSASigner(null);
  signer.init(false, PublicKeyParameter(ECPublicKey(Q, secp256k1)));
  return signer.verifySignature(hash, ECSignature(r, s));
  /* STEP BY STEP
  // 1.4.1 Enforce r and s are both integers in the interval [1, n − 1] (2, enforces '> 0')
  if (r.compareTo(n) >= 0) return false;
  if (s.compareTo(n) >= 0) return false;

  // 1.4.2 H = Hash(M), already done by the user
  // 1.4.3 e = H
  BigInt e = fromBuffer(hash);

  BigInt sInv = s.modInverse(n);
  BigInt u1 = (e * sInv) % n;
  BigInt u2 = (r * sInv) % n;

  // 1.4.5 Compute R = (xR, yR)
  //               R = u1G + u2Q
  ECPoint R = G * u1 + Q * u2;

  // 1.4.5 (cont.) Enforce R is not at infinity
  if (R.isInfinity) return false;

  // 1.4.6 Convert the field element R.x to an integer
  BigInt xR = R.x.toBigInteger();

  // 1.4.7 Set v = xR mod n
  BigInt v = xR % n;

  // 1.4.8 If v = r, output "valid", and if v != r, output "invalid"
  return v.compareTo(r) == 0;
  */
}

/// Decode a BigInt from bytes in big-endian encoding.
BigInt _decodeBigInt(List<int> bytes) {
  BigInt result = BigInt.from(0);
  for (int i = 0; i < bytes.length; i++) {
    result += BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
  }
  return result;
}

var _byteMask = BigInt.from(0xff);

/// Encode a BigInt into bytes using big-endian encoding.
Uint8List _encodeBigInt(BigInt number) {
  int needsPaddingByte;
  int rawSize;

  if (number > BigInt.zero) {
    rawSize = (number.bitLength + 7) >> 3;
    needsPaddingByte = ((number >> (rawSize - 1) * 8) & negativeFlag) == negativeFlag ? 1 : 0;

    if (rawSize < 32) {
      needsPaddingByte = 1;
    }
  } else {
    needsPaddingByte = 0;
    rawSize = (number.bitLength + 8) >> 3;
  }

  final size = rawSize < 32 ? rawSize + needsPaddingByte : rawSize;
  var result = Uint8List(size);
  for (int i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    number = number >> 8;
  }
  return result;
}

BigInt fromBuffer(Uint8List d) {
  return _decodeBigInt(d);
}

Uint8List toBuffer(BigInt d) {
  return _encodeBigInt(d);
}

ECPoint? decodeFrom(Uint8List P) {
  return secp256k1.curve.decodePoint(P);
}

Uint8List getEncoded(ECPoint? P, compressed) {
  return P!.getEncoded(compressed);
}

ECSignature deterministicSignature(Uint8List hash, Uint8List x) {

  final pkp = PrivateKeyParameter(ECPrivateKey(_decodeBigInt(x), secp256k1));
  final salt = Uint8List(16);

  // Loop through salts until a low r-value is found
  while (true) {

    final kMacDigest = Blake2bDigest(digestSize: 32, salt: salt);
    final signer = ECDSASigner(null, HMac(kMacDigest, 64));
    signer.init(true, pkp);
    final sig = signer.generateSignature(hash) as ECSignature;

    // Shift off all bits but the most significant and check that it is not set
    if ((sig.r >> 255).toInt() == 0)
      // r value was low, so return with this signature
      return sig;

    // If the r value was high, try again after incrementing the salt
    for (int i = 0; salt[i]++ == 255; i++);

  }

}

int _compare(Uint8List a, Uint8List b) {
  BigInt aa = fromBuffer(a);
  BigInt bb = fromBuffer(b);
  if (aa == bb) return 0;
  if (aa > bb) return 1;
  return -1;
}
