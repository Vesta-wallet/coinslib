import 'package:test/test.dart';
import 'package:coinslib/src/templates/pay_to_script_hash.dart';
import 'multisig_examples.dart';
import 'package:hex/hex.dart';

main() {
  // The only P2SH inputs allowed right now are standard multisig ones

  expectChunks(List<dynamic> chunks, success) => expect(
        inputCheck(
          chunks.map((c) => c is String ? HEX.decode(c) : c).toList(),
        ),
        success,
      );

  test('pay_to_script_hash inputCheck success', () {
    expectSuccess(chunks) => expectChunks(chunks, true);

    // Single signature
    expectSuccess([0, validSig, validOneOfOneScript]);
    // Allow no signatures
    expectSuccess([0, validOneOfOneScript]);
    // Double signature
    expectSuccess([0, validSig, validSig, validTwoOfTwoScript]);
    // Allow partial signature
    expectSuccess([0, validSig, validTwoOfTwoScript]);
  });

  test('pay_to_script_hash inputCheck success', () {
    expectFail(chunks) => expectChunks(chunks, false);

    // No null dummy
    expectFail([validSig, validOneOfOneScript]);
    // Too many signatures
    expectFail([0, validSig, validSig, validOneOfOneScript]);
    // Invalid signature
    expectFail([0, invalidSig, validOneOfOneScript]);
    // Invalid script
    expectFail([0, validSig, 0]);
  });
}
