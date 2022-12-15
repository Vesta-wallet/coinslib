import 'dart:typed_data';
import '../src/utils/script.dart' as bscript;
import 'templates/pubkeyhash.dart' as pubkeyhash;
import 'templates/pubkey.dart' as pubkey;
import 'templates/witnesspubkeyhash.dart' as witness_pubkey_hash;
import 'templates/witness_script_hash.dart' as witness_script_hash;

const scriptTypes = {
  'P2SM': 'multisig',
  'NONSTANDARD': 'nonstandard',
  'NULLDATA': 'nulldata',
  'P2PK': 'pubkey',
  'P2PKH': 'pubkeyhash',
  'P2SH': 'scripthash',
  'P2WPKH': 'witnesspubkeyhash',
  'P2WSH': 'witnessscripthash',
  'WITNESS_COMMITMENT': 'witnesscommitment'
};

String? classifyOutput(Uint8List script) {
  if (witness_pubkey_hash.outputCheck(script)) return scriptTypes['P2WPKH'];
  if (pubkeyhash.outputCheck(script)) return scriptTypes['P2PKH'];
  final chunks = bscript.decompile(script);
  if (chunks == null) throw ArgumentError('Invalid script');
  return scriptTypes['NONSTANDARD'];
}

String? classifyInput(Uint8List script) {
  final chunks = bscript.decompile(script);
  if (chunks == null) throw ArgumentError('Invalid script');
  if (pubkeyhash.inputCheck(chunks)) return scriptTypes['P2PKH'];
  if (pubkey.inputCheck(chunks)) return scriptTypes['P2PK'];
  return scriptTypes['NONSTANDARD'];
}

String? classifyWitness(List<Uint8List> script) {
  if (witness_pubkey_hash.inputCheck(script)) return scriptTypes['P2WPKH'];
  if (witness_script_hash.inputCheck(script)) return scriptTypes['P2WSH'];
  return scriptTypes['NONSTANDARD'];
}
