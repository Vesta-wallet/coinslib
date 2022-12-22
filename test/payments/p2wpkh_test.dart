import 'package:coinslib/src/payments/p2wpkh.dart';
import 'package:test/test.dart';
import 'package:hex/hex.dart';
import 'dart:typed_data';
import 'package:coinslib/src/models/networks.dart';

main() {
  test("P2WPKH.fromPublicKeyHash", () {
    final p2wpkh = P2WPKH.fromPublicKeyHash(
      HEX.decode("ea6d525c0c955d90d3dbd29a81ef8bfb79003727") as Uint8List,
    );
    expect(
      p2wpkh.address(bitcoin),
      "bc1qafk4yhqvj4wep57m62dgrmutldusqde8adh20d",
    );
    expect(
      p2wpkh.outputScript,
      HEX.decode("0014ea6d525c0c955d90d3dbd29a81ef8bfb79003727") as Uint8List,
    );
  });

  test("P2WPKH.fromPublicKey", () {
    final p2wpkh = P2WPKH.fromPublicKey(
      HEX.decode(
        "030000000000000000000000000000000000000000000000000000000000000001",
      ) as Uint8List,
    );
    expect(
      p2wpkh.address(bitcoin),
      "bc1qz69ej270c3q9qvgt822t6pm3zdksk2x35j2jlm",
    );
    expect(
      p2wpkh.pubKeyHash,
      HEX.decode("168b992bcfc44050310b3a94bd0771136d0b28d1") as Uint8List,
    );
    expect(
      p2wpkh.outputScript,
      HEX.decode("0014168b992bcfc44050310b3a94bd0771136d0b28d1") as Uint8List,
    );
  });

  test("invalid P2WPKH hash length", () {
    expect(
      () => P2WPKH.fromPublicKeyHash(
        HEX.decode("168b992bcfc44050310b3a94bd0771136d0b28") as Uint8List,
      ),
      throwsA(
        predicate(
          (e) =>
              e is ArgumentError &&
              e.message == 'Invalid P2WPKH public key hash length',
        ),
      ),
    );
  });
}
