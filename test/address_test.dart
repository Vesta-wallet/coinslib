import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'package:coinslib/src/address.dart' show Address;
import 'package:coinslib/src/models/networks.dart' as networks;

main() {
  group('Address', () {
    group('validateAddress', () {
      test('base58 addresses and valid network', () {
        expect(
          Address.validateAddress(
            'mhv6wtF2xzEqMNd3TbXx9TjLLo6mp2MUuT',
            networks.testnet,
          ),
          true,
        );
        expect(
          Address.validateAddress('1K6kARGhcX9nJpJeirgcYdGAgUsXD59nHZ'),
          true,
        );
        // P2SH
        expect(
          Address.validateAddress('3L1YkZjdeNSqaZcNKZFXQfyokx3zVYm7r6'),
          true,
        );
      });

      test('base58 addresses and invalid network', () {
        expect(
          Address.validateAddress(
            'mhv6wtF2xzEqMNd3TbXx9TjLLo6mp2MUuT',
            networks.bitcoin,
          ),
          false,
        );
        expect(
          Address.validateAddress(
            '1K6kARGhcX9nJpJeirgcYdGAgUsXD59nHZ',
            networks.testnet,
          ),
          false,
        );
      });

      test('bech32 addresses and valid network', () {
        expect(
          Address.validateAddress(
            'tb1qgmp0h7lvexdxx9y05pmdukx09xcteu9sx2h4ya',
            networks.testnet,
          ),
          true,
        );
        expect(
          Address.validateAddress(
            'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
          ),
          true,
        );
        expect(
          Address.validateAddress(
            'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
            networks.testnet,
          ),
          true,
        );
      });

      test('bech32 addresses and invalid network', () {
        expect(
          Address.validateAddress(
            'tb1qgmp0h7lvexdxx9y05pmdukx09xcteu9sx2h4ya',
          ),
          false,
        );
        expect(
          Address.validateAddress(
            'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
            networks.testnet,
          ),
          false,
        );
      });

      test('invalid addresses', () {
        expect(Address.validateAddress('3333333casca'), false);
      });

      test('wrong size base58 address', () {
        expect(
          Address.validateAddress('12D2adLM3UKy4Z4giRbReR6gjWx1w6Dz'),
          false,
          reason: "P2PKH too short",
        );

        expect(
          Address.validateAddress('1QXEx2ZQ9mEdvMSaVKHznFv6iZq2LQbDz8'),
          false,
          reason: "P2PKH too long",
        );

        expect(
          Address.validateAddress('TTazDDREDxxh1mPyGySut6H98h4UKPG6'),
          false,
          reason: "P2SH too short",
        );

        expect(
          Address.validateAddress('9tT9KH26AxgN8j9uTpKdwUkK6LFcSKp4FpF'),
          false,
          reason: "P2SH too long",
        );
      });

      test('wrong size bech32 addresses', () {
        // 31 bytes
        expect(
          Address.validateAddress(
            'bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpqy20t',
          ),
          false,
          reason: "P2WSH too short",
        );

        // 33 bytes
        expect(
          Address.validateAddress(
            'bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq88p3kr',
          ),
          false,
          reason: "P2WSH too long",
        );
      });
    });

    group('addressToOutputScript', () {
      expectScript(address, expectedScript) {
        final actual = Address.addressToOutputScript(address);
        expect(HEX.encode(actual), expectedScript);
      }

      test('returns p2pkh scripts', () {
        expectP2PKH(address, expectedHash) =>
            expectScript(address, "76a914${expectedHash}88ac");

        expectP2PKH(
          "1111111111111111111114oLvT2",
          "0000000000000000000000000000000000000000",
        );
        expectP2PKH(
          "1QLbz7JHiBTspS962RLKV8GndWFwi5j6Qr",
          "ffffffffffffffffffffffffffffffffffffffff",
        );
      });

      test('returns p2sh scripts', () {
        expectP2SH(address, expectedHash) =>
            expectScript(address, "a914${expectedHash}87");

        expectP2SH(
          "31h1vYVSYuKP6AhS86fbRdMw9XHieotbST",
          "0000000000000000000000000000000000000000",
        );
        expectP2SH(
          "3R2cuenjG5nFubqX9Wzuukdin2YfBbQ6Kw",
          "ffffffffffffffffffffffffffffffffffffffff",
        );
      });

      test('returns p2wsh scripts', () {
        expectP2WSH(address, expectedHash) =>
            expectScript(address, "0020$expectedHash");

        expectP2WSH(
          "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqthqst8",
          "0000000000000000000000000000000000000000000000000000000000000000",
        );

        expectP2WSH(
          "bc1qlllllllllllllllllllllllllllllllllllllllllllllllllllsffrpzs",
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
      });

      test('returns p2wpkh scripts', () {
        expectP2WPKH(address, expectedHash) =>
            expectScript(address, "0014$expectedHash");
        expectP2WPKH(
          "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs",
          "0000000000000000000000000000000000000000",
        );
        expectP2WPKH(
          "bc1qllllllllllllllllllllllllllllllllfglmy6",
          "ffffffffffffffffffffffffffffffffffffffff",
        );
      });
    });
  });
}
