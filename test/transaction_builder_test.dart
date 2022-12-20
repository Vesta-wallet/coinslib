import 'package:coinslib/src/utils/constants/op.dart';
import 'package:test/test.dart';
import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:coinslib/src/models/networks.dart';
import 'package:coinslib/src/ecpair.dart';
import 'package:coinslib/src/transaction.dart';
import 'package:coinslib/src/address.dart';
import 'package:coinslib/src/transaction_builder.dart';
import 'package:coinslib/src/utils/script.dart' as bscript;
import 'package:coinslib/src/payments/p2pkh.dart';

final networks = {'bitcoin': bitcoin, 'testnet': testnet};

constructSign(f, TransactionBuilder txb) {
  final network = networks[f['network']];
  final inputs = f['inputs'] as List<dynamic>;

  for (var i = 0; i < inputs.length; i++) {
    if (inputs[i]['signs'] == null) continue;
    for (final sign in inputs[i]['signs']) {
      ECPair keyPair = ECPair.fromWIF(sign['keyPair'], network: network);
      int? value = sign['value'];
      txb.sign(
        vin: i,
        keyPair: keyPair,
        witnessValue: value != null ? BigInt.from(value) : null,
        witnessScript: compileWitnessScriptFromInput(inputs[i]),
        hashType: sign['hashType'],
      );
    }
  }

  return txb;
}

TransactionBuilder construct(f, [bool dontSign = false]) {
  final network = networks[f['network']];
  final txb = TransactionBuilder(network: network);

  if (f['version'] != null) txb.setVersion(f['version']);

  for (final dynamic input in f['inputs']) {
    dynamic prevTx;

    if (input['txRaw'] != null) {
      final constructed = construct(input['txRaw']);
      prevTx = input['txRaw']['incomplete']
          ? constructed.buildIncomplete()
          : constructed.build();
    } else if (input['txHex'] != null) {
      prevTx = Transaction.fromHex(input['txHex']);
    } else {
      prevTx = input['txId'];
    }

    Uint8List? prevTxScript;
    if (input['prevTxScript'] != null) {
      prevTxScript = bscript.fromASM(input['prevTxScript']);
    }

    txb.addInput(prevTx, input['vout'], input['sequence'], prevTxScript);
  }

  for (final dynamic output in f['outputs']) {
    txb.addOutput(
      output['address'] ?? bscript.fromASM(output['script']),
      BigInt.from(output['value']),
    );
  }

  return dontSign ? txb : constructSign(f, txb);
}

Uint8List? compileWitnessScriptFromInput(dynamic input) {
  final witnessScriptASM = input['witnessScript'];
  return witnessScriptASM == null ? null : bscript.fromASM(witnessScriptASM);
}

main() {
  final fixtures = json.decode(
    File('test/fixtures/transaction_builder.json')
        .readAsStringSync(encoding: utf8),
  );

  final keyPair = ECPair.fromPrivateKey(
    HEX.decode(
      '0000000000000000000000000000000000000000000000000000000000000001',
    ) as Uint8List,
  );

  final scripts = [
    '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH',
    '1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP'
  ].map((x) => Address.addressToOutputScript(x));

  final txHash = HEX.decode(
    '0e7cea811c0be9f73c0aca591034396e7264473fc25c1ca45195d7417b36cbe2',
  );

  group('TransactionBuilder.fromTransaction', () {
    for (final f in fixtures['valid']['build']) {
      test('returns TransactionBuilder, with ${f['description']}', () {
        final network = networks[f['network'] ?? 'bitcoin'];
        final tx = Transaction.fromHex(f['txHex']);
        final txb = TransactionBuilder.fromTransaction(tx, network);
        final txAfter =
            f['incomplete'] != null ? txb.buildIncomplete() : txb.build();
        expect(txAfter.toHex(), f['txHex']);
        expect(txb.network, network);
      });
    }

    for (final f in (fixtures['valid']['fromTransaction'] as List<dynamic>)) {
      test('returns TransactionBuilder, with ${f['description']}', () {
        final tx = Transaction();
        final fInputList = f['inputs'] as List<dynamic>;
        final fOutputList = f['inputs'] as List<dynamic>;

        for (final input in fInputList) {
          final txHash2 =
              Uint8List.fromList(HEX.decode(input['txId']).reversed.toList());
          tx.addInput(
            txHash2,
            input['vout'],
            null,
            bscript.fromASM(input['scriptSig']),
          );
        }

        for (var output in fOutputList) {
          tx.addOutput(bscript.fromASM(output['script']), output['value']);
        }

        final txb = TransactionBuilder.fromTransaction(tx);
        final txAfter = f['incomplete'] ? txb.buildIncomplete() : txb.build();

        for (var i = 0; i < txAfter.ins.length; i++) {
          test(
            bscript.toASM(txAfter.ins[i].script!),
            f['inputs'][i]['scriptSigAfter'],
          );
        }
        for (var i = 0; i < txAfter.outs.length; i++) {
          test(
            bscript.toASM(txAfter.outs[i].script!),
            f['outputs'][i]['script'],
          );
        }
      });
    }

    for (final f in (fixtures['invalid']['fromTransaction'] as List)) {
      test('throws ${f['exception']}', () {
        final tx = Transaction.fromHex(f['txHex']);
        try {
          expect(TransactionBuilder.fromTransaction(tx), isArgumentError);
        } catch (err) {
          expect((err as ArgumentError).message, f['exception']);
        }
      });
    }
  });

  group('TransactionBuilder.addInput', () {
    late TransactionBuilder txb;
    setUp(() {
      txb = TransactionBuilder();
    });

    test('accepts a txHash, index [and sequence number]', () {
      final vin = txb.addInput(txHash, 1, 54);
      expect(vin, 0);
      final txIn = txb.tx.ins[0];
      expect(txIn.hash, txHash);
      expect(txIn.index, 1);
      expect(txIn.sequence, 54);
      expect(txb.inputs[0].prevOutScript, null);
    });

    test('accepts a txHash, index [, sequence number and scriptPubKey]', () {
      final vin = txb.addInput(txHash, 1, 54, scripts.elementAt(1));
      expect(vin, 0);
      final txIn = txb.tx.ins[0];
      expect(txIn.hash, txHash);
      expect(txIn.index, 1);
      expect(txIn.sequence, 54);
      expect(txb.inputs[0].prevOutScript, scripts.elementAt(1));
    });

    test('accepts a prevTx, index [and sequence number]', () {
      final prevTx = Transaction();
      prevTx.addOutput(scripts.elementAt(0), BigInt.zero);
      prevTx.addOutput(scripts.elementAt(1), BigInt.one);

      final vin = txb.addInput(prevTx, 1, 54);
      expect(vin, 0);

      final txIn = txb.tx.ins[0];
      expect(txIn.hash, prevTx.getHash());
      expect(txIn.index, 1);
      expect(txIn.sequence, 54);
      expect(txb.inputs[0].prevOutScript, scripts.elementAt(1));
    });

    test('returns the input index', () {
      expect(txb.addInput(txHash, 0), 0);
      expect(txb.addInput(txHash, 1), 1);
    });

    test('throws if SIGHASH_ALL has been used to sign any existing scriptSigs',
        () {
      txb.addInput(txHash, 0);
      txb.addOutput(scripts.elementAt(0), BigInt.from(1000));
      txb.sign(vin: 0, keyPair: keyPair);
      try {
        expect(txb.addInput(txHash, 0), isArgumentError);
      } catch (err) {
        expect(
          (err as ArgumentError).message,
          'No, this would invalidate signatures',
        );
      }
    });
  });

  group('TransactionBuilder.addOutput', () {
    late TransactionBuilder txb;
    setUp(() {
      txb = TransactionBuilder();
    });

    test('accepts an address string and value', () {
      final address = P2PKH.fromPublicKey(keyPair.publicKey!).address(bitcoin);
      final vout = txb.addOutput(address, BigInt.from(1000));
      expect(vout, 0);
      final txout = txb.tx.outs[0];
      expect(txout.script, scripts.elementAt(0));
      expect(txout.value, BigInt.from(1000));
    });

    test('accepts a ScriptPubKey and value', () {
      final vout = txb.addOutput(scripts.elementAt(0), BigInt.from(1000));
      expect(vout, 0);
      final txout = txb.tx.outs[0];
      expect(txout.script, scripts.elementAt(0));
      expect(txout.value, BigInt.from(1000));
    });

    test('throws if address is of the wrong network', () {
      try {
        expect(
          txb.addOutput(
            '2NGHjvjw83pcVFgMcA7QvSMh2c246rxLVz9',
            BigInt.from(1000),
          ),
          isArgumentError,
        );
      } catch (err) {
        expect(
          (err as ArgumentError).message,
          'Invalid version or Network mismatch',
        );
      }
    });

    test('add second output after signed first input with SIGHASH_NONE', () {
      txb.addInput(txHash, 0);
      txb.addOutput(scripts.elementAt(0), BigInt.from(2000));
      txb.sign(vin: 0, keyPair: keyPair, hashType: sigHashNone);
      expect(txb.addOutput(scripts.elementAt(1), BigInt.from(9000)), 1);
    });

    test('add first output after signed first input with SIGHASH_NONE', () {
      txb.addInput(txHash, 0);
      txb.sign(vin: 0, keyPair: keyPair, hashType: sigHashNone);
      expect(txb.addOutput(scripts.elementAt(0), BigInt.from(2000)), 0);
    });

    test('add second output after signed first input with SIGHASH_SINGLE', () {
      txb.addInput(txHash, 0);
      txb.addOutput(scripts.elementAt(0), BigInt.from(2000));
      txb.sign(vin: 0, keyPair: keyPair, hashType: sigHashSingle);
      expect(txb.addOutput(scripts.elementAt(1), BigInt.from(9000)), 1);
    });

    test('add first output after signed first input with SIGHASH_SINGLE', () {
      txb.addInput(txHash, 0);
      txb.sign(vin: 0, keyPair: keyPair, hashType: sigHashSingle);
      try {
        expect(
          txb.addOutput(scripts.elementAt(0), BigInt.from(2000)),
          isArgumentError,
        );
      } catch (err) {
        expect(
          (err as ArgumentError).message,
          'No, this would invalidate signatures',
        );
      }
    });

    test('throws if SIGHASH_ALL has been used to sign any existing scriptSigs',
        () {
      txb.addInput(txHash, 0);
      txb.addOutput(scripts.elementAt(0), BigInt.from(2000));
      txb.sign(vin: 0, keyPair: keyPair);
      try {
        expect(
          txb.addOutput(scripts.elementAt(1), BigInt.from(9000)),
          isArgumentError,
        );
      } catch (err) {
        expect(
          (err as ArgumentError).message,
          'No, this would invalidate signatures',
        );
      }
    });
  });

  group('TransactionBuilder.addNullOutput', () {
    late TransactionBuilder txb;
    late String data;
    late String data2;

    setUp(() {
      txb = TransactionBuilder();
      data =
          'Hey this is a random string without coins. Extended to 80 characters............';
      data2 = 'And this is another string.';
    });

    expectOutputScript(input, Uint8List expectPushData) {
      final opReturn = ops['OP_RETURN']!;
      final expectScript = bscript.compile([opReturn, expectPushData]);
      final vout = txb.addNullOutput(input);
      expect(vout, 0);
      final txout = txb.tx.outs[0];
      expect(txout.script, expectScript);
      expect(txout.value, BigInt.zero);
    }

    test('accepts a string', () {
      final rawData = Uint8List.fromList(utf8.encode(data));
      expectOutputScript(data, rawData);
    });

    test('accepts Uint8List data', () {
      final rawData = Uint8List.fromList(List.generate(80, (i) => i));
      expectOutputScript(rawData, rawData);
    });

    test('throws if too much data is provided', () {
      try {
        expect(
          txb.addNullOutput(
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi sagittis placerat.',
          ),
          isArgumentError,
        );
      } catch (err) {
        expect(
          (err as ArgumentError).message,
          'Too much data, max OP_RETURN size is 80',
        );
      }
    });

    test('add second output after signed first input with SIGHASH_NONE', () {
      txb.addInput(txHash, 0);
      txb.addNullOutput(data);
      txb.sign(vin: 0, keyPair: keyPair, hashType: sigHashNone);
      expect(txb.addNullOutput(data2), 1);
    });

    test('add first output after signed first input with SIGHASH_NONE', () {
      txb.addInput(txHash, 0);
      txb.sign(vin: 0, keyPair: keyPair, hashType: sigHashNone);
      expect(txb.addNullOutput(data), 0);
    });

    test('add second output after signed first input with SIGHASH_SINGLE', () {
      txb.addInput(txHash, 0);
      txb.addNullOutput(data);
      txb.sign(vin: 0, keyPair: keyPair, hashType: sigHashSingle);
      expect(txb.addNullOutput(data2), 1);
    });

    test('add first output after signed first input with SIGHASH_SINGLE', () {
      txb.addInput(txHash, 0);
      txb.sign(vin: 0, keyPair: keyPair, hashType: sigHashSingle);
      try {
        expect(txb.addNullOutput(data), isArgumentError);
      } catch (err) {
        expect(
          (err as ArgumentError).message,
          'No, this would invalidate signatures',
        );
      }
    });

    test('throws if SIGHASH_ALL has been used to sign any existing scriptSigs',
        () {
      txb.addInput(txHash, 0);
      txb.addNullOutput(data);
      txb.sign(vin: 0, keyPair: keyPair);
      try {
        expect(txb.addNullOutput(data2), isArgumentError);
      } catch (err) {
        expect(
          (err as ArgumentError).message,
          'No, this would invalidate signatures',
        );
      }
    });
  });

  group('TransactionBuilder.setLockTime', () {
    test('throws if if there exist any scriptSigs', () {
      final txb = TransactionBuilder();
      txb.addInput(txHash, 0);
      txb.addOutput(scripts.elementAt(0), BigInt.from(100));
      txb.sign(vin: 0, keyPair: keyPair);
      try {
        expect(txb.setLockTime(65535), isArgumentError);
      } catch (err) {
        expect(
          (err as ArgumentError).message,
          'Can\'t set lock time; this would invalidate signatures',
        );
      }
    });
  });

  group('TransactionBuilder.sign', () {
    // Valid tests are implicit in the invalid fixtures that test that signing
    // an already signed input is invalid
    for (final dynamic f in fixtures['invalid']['sign']) {
      test('throws ${f['exception']} ${f['description'] ?? ''}', () {
        final txb = construct(f, true);
        final inputs = f['inputs'] as List;

        for (var i = 0; i < inputs.length; i++) {
          final witnessScript = compileWitnessScriptFromInput(inputs[i]);

          for (final dynamic sign in inputs[i]['signs']) {
            final keyPairNetwork = networks[sign['network'] ?? f['network']];
            final keyPair2 =
                ECPair.fromWIF(sign['keyPair'], network: keyPairNetwork);

            Matcher match = sign['throws'] == null || !sign['throws']
                ? returnsNormally
                : throwsA(
                    allOf(
                      isArgumentError,
                      predicate(
                        (ArgumentError err) => err.message == f['exception'],
                      ),
                    ),
                  );

            final valueNum = sign['value'];
            final valueBI = valueNum == null ? null : BigInt.from(valueNum);

            expect(
              () => txb.sign(
                vin: i,
                keyPair: keyPair2,
                hashType: sign['hashType'],
                witnessValue: valueBI,
                witnessScript: witnessScript,
              ),
              match,
            );
          }
        }
      });
    }
  });

  group('TransactionBuilder.build', () {
    for (final f in fixtures['valid']['build']) {
      test('builds ${f['description']}', () {
        final txb = construct(f);
        final tx =
            f['incomplete'] != null ? txb.buildIncomplete() : txb.build();
        expect(tx.toHex(), f['txHex']);
      });
    }

    for (final f in fixtures['invalid']['build']) {
      group('for ${f['description'] ?? f['exception']}', () {
        test('throws ${f['exception']}', () {
          try {
            TransactionBuilder txb;
            if (f['txHex'] != null) {
              txb = TransactionBuilder.fromTransaction(
                Transaction.fromHex(f['txHex']),
              );
            } else {
              txb = construct(f);
            }
            expect(txb.build(), isArgumentError);
          } catch (err) {
            expect((err as ArgumentError).message, f['exception']);
          }
        });

        // if throws on incomplete too, enforce that
        if (f['incomplete'] != null && f['incomplete']) {
          test('throws ${f['exception']}', () {
            try {
              TransactionBuilder txb;
              if (f['txHex'] != null) {
                txb = TransactionBuilder.fromTransaction(
                  Transaction.fromHex(f['txHex']),
                );
              } else {
                txb = construct(f);
              }
              expect(txb.buildIncomplete(), isArgumentError);
            } catch (err) {
              expect((err as ArgumentError).message, f['exception']);
            }
          });
        } else {
          test('does not throw if buildIncomplete', () {
            TransactionBuilder txb;
            if (f['txHex'] != null) {
              txb = TransactionBuilder.fromTransaction(
                Transaction.fromHex(f['txHex']),
              );
            } else {
              txb = construct(f);
            }
            txb.buildIncomplete();
          });
        }
      });
    }
  });
}
