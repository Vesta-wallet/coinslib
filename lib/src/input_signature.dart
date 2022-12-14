import 'dart:typed_data';
import 'utils/script.dart' as bscript;
import './utils/ecurve.dart' as ecc;

/// Encapsulates the signature for an input with a given SIGHASH [hashType].
class InputSignature {
  final Uint8List rawSignature;
  final int hashType;
  Uint8List? encodedCache;

  /// Create an input signature from the [rawSignature] bytes whilst also
  /// recording the SIGHASH [hashType] and transaction signature [hash] used for
  /// this signature
  InputSignature({
    required this.rawSignature,
    required this.hashType,
  }) {
    if (rawSignature.length != 64) {
      throw ArgumentError("Signature size should be 64 bytes");
    }
    if (!bscript.isDefinedHashType(hashType)) {
      throw ArgumentError("Hash type is invalid");
    }
  }

  static InputSignature decode(Uint8List bytes) {
    if (!bscript.isCanonicalScriptSignature(bytes)) {
      throw ArgumentError('Cannot decode invalid signature');
    }

    int rLen = bytes[3];
    int sLen = bytes[5 + rLen];

    final derR = bytes.sublist(4, 4 + rLen);
    final derS = bytes.sublist(6 + rLen, 6 + rLen + sLen);

    final r = bscript.toBigEndianFromDER(derR, 32);
    final s = bscript.toBigEndianFromDER(derS, 32);

    return InputSignature(
      rawSignature: Uint8List.fromList(r + s),
      hashType: bytes.last,
    );
  }

  /// Encodes the signature into the DER representation
  Uint8List encode() {
    // For now, just going to use the existing code
    encodedCache ??= bscript.encodeSignature(rawSignature, hashType);
    return encodedCache!;
  }

  /// Returns true if the [pk] public key signed this signature for the [hash]
  bool verify(Uint8List pk, Uint8List hash) =>
      ecc.verify(hash, pk, rawSignature);
}
