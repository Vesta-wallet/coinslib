import 'package:test/test.dart';
import 'package:hex/hex.dart';
import 'dart:typed_data';
import 'dart:io';
import 'dart:convert';
import 'package:coinslib/src/ecpair.dart' show ECPair;
import 'package:coinslib/src/models/networks.dart' as networks;

final one = HEX.decode(
  '0000000000000000000000000000000000000000000000000000000000000001',
) as Uint8List;

main() {
  final fixtures = json.decode(
      File('test/fixtures/ecpair.json').readAsStringSync(encoding: utf8),
  );

  group('ECPair', () {
    group('fromPrivateKey', () {
      test('defaults to compressed', () {
        final keyPair = ECPair.fromPrivateKey(one);
        expect(keyPair.compressed, true);
      });
      test('supports the uncompressed option', () {
        final keyPair = ECPair.fromPrivateKey(one, compressed: false);
        expect(keyPair.compressed, false);
      });
      test('supports the network option', () {
        final keyPair = ECPair.fromPrivateKey(
          one, network: networks.testnet, compressed: false,
        );
        expect(keyPair.network, networks.testnet);
      });
      for (var f in (fixtures['valid'] as List)) {
        test('derives public key for ${f['WIF']}', () {
          final d = HEX.decode(f['d']) as Uint8List;
          final keyPair = ECPair.fromPrivateKey(d, compressed: f['compressed']);
          expect(HEX.encode(keyPair.publicKey!), f['Q']);
        });
      }
      for (var f in (fixtures['invalid']['fromPrivateKey'] as List)) {
        test('throws ${f['exception']}', () {
          final d = HEX.decode(f['d']) as Uint8List;
          try {
            expect(ECPair.fromPrivateKey(d), isArgumentError);
          } catch (err) {
            expect((err as ArgumentError).message, f['exception']);
          }
        });
      }
    });

    group('fromPublicKey', () {
      for (var f in (fixtures['invalid']['fromPublicKey'] as List)) {
        test('throws ${f['exception']}', () {
          final Q = HEX.decode(f['Q']) as Uint8List;
          try {
            expect(ECPair.fromPublicKey(Q), isArgumentError);
          } catch (err) {
            expect((err as ArgumentError).message, f['exception']);
          }
        });
      }
    });

    group('fromWIF', () {
      for (var f in (fixtures['valid'] as List)) {
        test('imports ${f['WIF']}', () {
          final keyPair = ECPair.fromWIF(f['WIF']);
          var network = _getNetwork(f);
          expect(HEX.encode(keyPair.privateKey!), f['d']);
          expect(keyPair.compressed, f['compressed']);
          expect(keyPair.network, network);
        });
      }
      for (var f in (fixtures['invalid']['fromWIF'] as List)) {
        test('throws ${f['exception']}', () {
          var network = _getNetwork(f);
          try {
            expect(ECPair.fromWIF(f['WIF'], network: network), isArgumentError);
          } catch (err) {
            expect((err as ArgumentError).message, f['exception']);
          }
        });
      }
    });

    group('toWIF', () {
      for (var f in (fixtures['valid'] as List)) {
        test('export ${f['WIF']}', () {
          final keyPair = ECPair.fromWIF(f['WIF']);
          expect(keyPair.toWIF(), f['WIF']);
        });
      }
    });

    group('makeRandom', () {
      final d = Uint8List.fromList(List.generate(32, (i) => 4));
      final exWIF = 'KwMWvwRJeFqxYyhZgNwYuYjbQENDAPAudQx5VEmKJrUZcq6aL2pv';
      test('allows a custom RNG to be used', () {
        final keyPair = ECPair.makeRandom(
          rng: (size) => d.sublist(0, size),
        );
        expect(keyPair.toWIF(), exWIF);
      });
      test('retains the same defaults as ECPair constructor', () {
        final keyPair = ECPair.makeRandom();
        expect(keyPair.compressed, true);
        expect(keyPair.network, networks.bitcoin);
      });
      test('supports the options parameter', () {
        final keyPair =
            ECPair.makeRandom(compressed: false, network: networks.testnet);
        expect(keyPair.compressed, false);
        expect(keyPair.network, networks.testnet);
      });
      test('throws if d is bad length', () {
        rng(int number) {
          return Uint8List(28);
        }

        try {
          ECPair.makeRandom(rng: rng);
        } catch (err) {
          expect((err as ArgumentError).message, 'Expected Buffer(Length: 32)');
        }
      });
    });

    group('.network', () {
      for (var f in (fixtures['valid'] as List)) {
        test('return ${f['network']} for ${f['WIF']}', () {
          var network = _getNetwork(f);
          final keyPair = ECPair.fromWIF(f['WIF']);
          expect(keyPair.network, network);
        });
      }
    });

    group('sign', () {
      final aliceKey = ECPair.fromWIF(
          'U9ofQxewXjF48KW7J5zd5FhnC3oCYsj15ESMtUvJnsfbjEDN43aW',
          network: networks.peercoin,
      );

      test('gives low r and s values and unique r values', () {
        Uint8List fakeHash = Uint8List(32);
        List<Uint8List> rValues = [];

        for (int i = 0; i < 256; i++) {
          fakeHash[0] = i;
          final sig = aliceKey.sign(fakeHash);
          final r = sig.sublist(0, 32);
          final s = sig.sublist(32, 64);
          rValues.add(r);
          // Require r and s values to be low
          expect(r[0] & 0x80, 0);
          expect(s[0] & 0x80, 0);
        }

        // Check r-value uniqueness
        void expectUnique(Uint8List a, Uint8List b) {
          expect(a.length, b.length);
          bool same = true;
          for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
              same = false;
              break;
            }
          }
          expect(same, isFalse);
        }

        for (int i = 0; i < rValues.length; i++) {
          for (int j = 0; j < i; j++) {
            expectUnique(rValues[i], rValues[j]);
          }
        }
      });
    });
  });
}

networks.NetworkType? _getNetwork(f) {
  if (f['network'] != null) {
    if (f['network'] == 'bitcoin') {
      return networks.bitcoin;
    } else if (f['network'] == 'testnet') {
      return networks.testnet;
    }
  }
  return null;
}
