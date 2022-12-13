// ignore_for_file: prefer_interpolation_to_compose_strings

import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'package:coinslib/src/templates/witness_script_hash.dart';

main() {
  // The only P2WSH inputs allowed right now are standard multisig ones

  expectWitness(List<String> witnessHex, bool success) => expect(
      inputCheck(
          witnessHex.map((hex) => HEX.decode(hex) as Uint8List).toList()),
      success);

  const String validSig =
      "3045022100a7cf5c28088647557b1b9eea8366d72a9a89ef380ec1c9f00e75a8458a33d6ca0220265a0174092fdcf5f00749463876d34302c64f590e43af7b59cdec7dea9ba2a201";

  // Mutate second byte slightly (invalid sig length)
  const String invalidSig =
      "3046022100a7cf5c28088647557b1b9eea8366d72a9a89ef380ec1c9f00e75a8458a33d6ca0220265a0174092fdcf5f00749463876d34302c64f590e43af7b59cdec7dea9ba2a201";

  const String validPubkeyPush =
      "2102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4";

  const String validOneOfOneScript =
      // OP_1
      "51" +
          validPubkeyPush +
          // OP_1 OP_CHECKMULTISIG
          "51AE";

  const String validTwoOfTwoScript =
      // OP_2
      "52" +
          validPubkeyPush +
          validPubkeyPush +
          // OP_2 OP_CHECKMULTISIG
          "52AE";

  test('witness_script_hash inputCheck success', () {
    expectSuccess(witnessHex) => expectWitness(witnessHex, true);

    // Single signature
    expectSuccess(["", validSig, validOneOfOneScript]);
    // Allow no signatures
    expectSuccess(["", validOneOfOneScript]);
    // Double signature
    expectSuccess(["", validSig, validSig, validTwoOfTwoScript]);
    // Allow partial signature
    expectSuccess(["", validSig, validTwoOfTwoScript]);
  });

  test('witness_script_hash inputCheck success', () {
    expectFail(witnessHex) => expectWitness(witnessHex, false);

    // No null dummy
    expectFail([validSig, validOneOfOneScript]);
    // BIP147: Do not allow anything other than null dummy.
    expectFail(["0001", validSig, validOneOfOneScript]);
    // Too many signatures
    expectFail(["00", validSig, validSig, validOneOfOneScript]);
    // Invalid signature
    expectFail(["00", invalidSig, validOneOfOneScript]);
    // Invalid script
    expectFail(["00", validSig, "00"]);
  });
}
