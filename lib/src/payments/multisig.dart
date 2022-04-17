import 'dart:typed_data';
import '../utils/ecurve.dart' show isPoint;
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';

/// Encapsulates a multi-signature redeem or witness script given a set of
/// public keys and signature threshold.
class MultisigScript {

  static const int _maxMultisigPubkeys = 20;

  static final _thresholdError = ArgumentError(
    'The threshold must be from 1 up-to the number of public keys'
  );
  static final _pubkeyNError = ArgumentError(
    'Must have 1-$_maxMultisigPubkeys public keys in a multisig script'
  );

  late List<Uint8List> pubkeys;
  late int threshold;

  /// Creates a multisig redeem script using CHECKMULTISIG for the [pubkeys]
  /// requiring [threshold] signatures. If [threshold] is not given, then all
  /// public keys are required.
  MultisigScript({
    required this.pubkeys, int threshold = -1
  }) : threshold = threshold < 0 ? pubkeys.length : threshold {

    if (threshold == 0 || threshold > pubkeys.length) throw _thresholdError;

    if (pubkeys.length > _maxMultisigPubkeys || pubkeys.isEmpty) {
      throw _pubkeyNError;
    }

    if (pubkeys.any((pk) => !isPoint(pk))) {
      throw ArgumentError('At least one public key argument is not valid');
    }

  }

  /// Returns a MultisigScript from the script bytes or ArgumentError if the
  /// script is not a multi-sig redeem or witness script
  MultisigScript.fromScriptBytes(Uint8List bytes) {

    final chunks = bscript.decompile(bytes);

    if (chunks == null) throw ArgumentError('Script is invalid');

    // Must have threshold, at least 1 public key, pubkey number and CHECKMULTISIG
    if (chunks.length < 4) throw ArgumentError('Too few script chunks');

    // Must end with CHECKMULTISIG
    if (chunks.last != OPS['OP_CHECKMULTISIG']) {
      throw ArgumentError('Script must end in a CHECKMULTISIG');
    }

    // Second to last must be number of public keys between 1-20
    int? pubkeyN = bscript.uint8FromChunk(chunks[chunks.length-2]);
    if (pubkeyN == null || pubkeyN < 1 || pubkeyN > _maxMultisigPubkeys) {
      throw _pubkeyNError;
    }

    // Must have the correct number of public keys
    if (chunks.length != pubkeyN+3) {
      throw ArgumentError(
        'The script size is inccorect for the number of public keys'
      );
    }

    // Extract public keys
    pubkeys = [];
    for (int i = 1; i < chunks.length-2; i++) {
      if (!bscript.isCanonicalPubKey(chunks[i])) {
        throw ArgumentError('Public key ${i - 1} is invalid');
      }
      pubkeys.add(chunks[i]);
    }

    // Theshold must be 1 upto the number of public keys
    int? threshold = bscript.uint8FromChunk(chunks[0]);
    if (threshold == null || threshold < 1 || threshold > pubkeyN) {
      throw _thresholdError;
    }

    this.threshold = threshold;

  }

  Uint8List get scriptBytes => bscript.compile([
      bscript.pushUint8(threshold),
      ...pubkeys,
      bscript.pushUint8(pubkeys.length),
      OPS['OP_CHECKMULTISIG']
  ]);

}

