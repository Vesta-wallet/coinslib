import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'package:coinslib/src/templates/witness_script_hash.dart';
import 'multisig_examples.dart';

main() {
  // The only P2WSH inputs allowed right now are standard multisig ones

  expectWitness(List<String> witnessHex, bool success) => expect(
        inputCheck(
          witnessHex.map((hex) => HEX.decode(hex) as Uint8List).toList(),
        ),
        success,
      );

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
