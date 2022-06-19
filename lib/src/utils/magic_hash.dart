import 'dart:typed_data';
import 'dart:convert';
import '../../src/crypto.dart';
import 'varuint.dart' as varint;
import '../../src/models/networks.dart';

Uint8List magicHash(String message, [NetworkType? network]) {

  network = network ?? bitcoin;

  final bb = BytesBuilder();

  encodeStr(String s) {
    bb.add(varint.encode(s.length));
    bb.add(utf8.encode(s));
  }

  encodeStr(network.messagePrefix);
  encodeStr(message);

  return hash256(bb.toBytes());

}
