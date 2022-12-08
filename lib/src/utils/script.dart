import 'dart:math';
import 'dart:typed_data';
import 'package:hex/hex.dart';
import './ecurve.dart' as ecc;
import 'constants/op.dart';
import 'push_data.dart' as push_data;
import 'check_types.dart';

Map<int, String> reverseOps =
    ops.map((String string, int number) => MapEntry(number, string));
final opIntBase = ops['OP_RESERVED'];
final zero = Uint8List.fromList([0]);

Uint8List compile(List<dynamic> chunks) {
  final dynamic bufferSize = chunks.fold<int>(0, (int acc, chunk) {
    if (chunk is int) return acc + 1;
    if (chunk.length == 1 && asMinimalOP(chunk) != null) {
      return acc + 1;
    }
    return acc + push_data.encodingLength(chunk.length) + chunk.length as int;
  });
  var buffer = Uint8List(bufferSize);

  var offset = 0;
  for (final chunk in chunks) {
    // data chunk
    if (chunk is Uint8List) {
      // adhere to BIP62.3, minimal push policy
      final opcode = asMinimalOP(chunk);
      if (opcode != null) {
        buffer.buffer.asByteData().setUint8(offset, opcode);
        offset += 1;
        continue;
      }
      push_data.EncodedPushData epd =
          push_data.encode(buffer, chunk.length, offset);
      offset += epd.size!;
      buffer = epd.buffer!;
      buffer.setRange(offset, offset + chunk.length, chunk);
      offset += chunk.length;
      // opcode
    } else {
      buffer.buffer.asByteData().setUint8(offset, chunk);
      offset += 1;
    }
  }

  if (offset != buffer.length) {
    throw ArgumentError("Could not decode chunks");
  }
  return buffer;
}

List<dynamic>? decompile(dynamic buffer) {
  List<dynamic> chunks = [];

  if (buffer == null) return chunks;
  if (buffer is List && buffer.length == 2) return buffer;

  var i = 0;
  while (i < buffer.length) {
    final opcode = buffer[i];

    // data chunk
    if ((opcode > ops['OP_0']) && (opcode <= ops['OP_PUSHDATA4'])) {
      final d = push_data.decode(buffer, i);

      // did reading a pushDataInt fail?
      if (d == null) return null;
      i += d.size!;

      // attempt to read too much data?
      if (i + d.number! > buffer.length) return null;

      final data = buffer.sublist(i, i + d.number!);
      i += d.number!;

      // decompile minimally
      final op = asMinimalOP(data);
      if (op != null) {
        chunks.add(op);
      } else {
        chunks.add(data);
      }

      // opcode
    } else {
      chunks.add(opcode);
      i += 1;
    }
  }
  return chunks;
}

/// Creates the chunk for a uint8. It does not test that the integer is within
/// the correct bounds.
Uint8List pushUint8(int i) => Uint8List.fromList([i]);

// Unfortunately using dynamic due to the existing code
int? uint8FromChunk(dynamic chunk) {

  if (chunk is Uint8List) {
    return  chunk.length == 1 ? chunk[0] : null;
  }

  if (chunk == ops['OP_0']) return 0;

  int i = chunk - opIntBase;
  if (i < 0 || i > 16) return null;
  return i;

}

Uint8List fromASM(String asm) {
  if (asm == '') return Uint8List.fromList([]);
  return compile(asm.split(' ').map((chunkStr) {
    if (ops[chunkStr] != null) return ops[chunkStr];
    return HEX.decode(chunkStr);
  }).toList());
}

String toASM(List<dynamic> c) {
  List<dynamic> chunks;
  if (c is Uint8List) {
    chunks = decompile(c)!;
  } else {
    chunks = c;
  }
  return chunks.map((chunk) {
    // data?
    if (chunk is Uint8List) {
      final op = asMinimalOP(chunk);
      if (op == null) return HEX.encode(chunk);
      chunk = op;
    }
    // opcode!
    return reverseOps[chunk];
  }).join(' ');
}

int? asMinimalOP(Uint8List buffer) {
  if (buffer.isEmpty) return ops['OP_0'];
  if (buffer.length != 1) return null;
  if (buffer[0] >= 1 && buffer[0] <= 16) return opIntBase! + buffer[0];
  if (buffer[0] == 0x81) return ops['OP_1NEGATE'];
  return null;
}

bool isDefinedHashType(hashType) {
  final hashTypeMod = hashType & ~0x80;
  // return hashTypeMod > SIGHASH_ALL && hashTypeMod < SIGHASH_SINGLE
  return hashTypeMod > 0x00 && hashTypeMod < 0x04;
}

bool isCanonicalPubKey(Uint8List buffer) {
  return ecc.isPoint(buffer);
}

bool isCanonicalScriptSignature(Uint8List buffer) {
  if (!isDefinedHashType(buffer[buffer.length - 1])) return false;
  return bip66check(buffer.sublist(0, buffer.length - 1));
}

bool bip66check(buffer) {
  if (buffer.length < 8) return false;
  if (buffer.length > 72) return false;
  if (buffer[0] != 0x30) return false;
  if (buffer[1] != buffer.length - 2) return false;
  if (buffer[2] != 0x02) return false;

  var lenR = buffer[3];
  if (lenR == 0) return false;
  if (5 + lenR >= buffer.length) return false;
  if (buffer[4 + lenR] != 0x02) return false;

  var lenS = buffer[5 + lenR];
  if (lenS == 0) return false;
  if ((6 + lenR + lenS) != buffer.length) return false;

  if (buffer[4] & 0x80 != 0) return false;
  if (lenR > 1 && (buffer[4] == 0x00) && buffer[5] & 0x80 == 0) return false;

  if (buffer[lenR + 6] & 0x80 != 0) return false;

  return !(
    lenS > 1 && (buffer[lenR + 6] == 0x00) && buffer[lenR + 7] & 0x80 == 0
  );

}

Uint8List bip66encode(r, s) {
  var lenR = r.length;
  var lenS = s.length;
  if (lenR == 0) throw ArgumentError('R length is zero');
  if (lenS == 0) throw ArgumentError('S length is zero');
  if (lenR > 33) throw ArgumentError('R length is too long');
  if (lenS > 33) throw ArgumentError('S length is too long');
  if (r[0] & 0x80 != 0) throw ArgumentError('R value is negative');
  if (s[0] & 0x80 != 0) throw ArgumentError('S value is negative');
  if (lenR > 1 && (r[0] == 0x00) && r[1] & 0x80 == 0) {
    throw ArgumentError('R value excessively padded');
  }
  if (lenS > 1 && (s[0] == 0x00) && s[1] & 0x80 == 0) {
    throw ArgumentError('S value excessively padded');
  }

  var signature = Uint8List(6 + (lenR as int) + (lenS as int));

  // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
  signature[0] = 0x30;
  signature[1] = signature.length - 2;
  signature[2] = 0x02;
  signature[3] = r.length;
  signature.setRange(4, 4 + lenR, r);
  signature[4 + lenR] = 0x02;
  signature[5 + lenR] = s.length;
  signature.setRange(6 + lenR, 6 + lenR + lenS, s);
  return signature;
}

Uint8List encodeSignature(Uint8List signature, int hashType) {
  if (!isUint(hashType, 8)) throw ArgumentError("Invalid hasType $hashType");
  if (signature.length != 64) throw ArgumentError("Invalid signature");
  final hashTypeMod = hashType & ~0x80;
  if (hashTypeMod <= 0 || hashTypeMod >= 4) {
    throw ArgumentError('Invalid hashType $hashType');
  }

  final hashTypeBuffer = Uint8List(1);
  hashTypeBuffer.buffer.asByteData().setUint8(0, hashType);
  final r = toDER(signature.sublist(0, 32));
  final s = toDER(signature.sublist(32, 64));
  List<int> combine = List.from(bip66encode(r, s));
  combine.addAll(List.from(hashTypeBuffer));
  return Uint8List.fromList(combine);
}

Uint8List toDER(Uint8List x) {
  var i = 0;
  while (x[i] == 0) {
    ++i;
  }
  if (i == x.length) return zero;
  x = x.sublist(i);
  List<int> combine = List.from(zero);
  combine.addAll(x);
  if (x[0] & 0x80 != 0) return Uint8List.fromList(combine);
  return x;
}

/// Convert [bytes] representing an integer into a list of [length] padded with
/// zeros on the front
Uint8List padZeroBigEndian(Uint8List bytes, int length) => Uint8List.fromList(
  List.filled(max(length - bytes.length, 0), 0) + bytes
);

/// Converts a DER encoded integer ([der]) to a big endian Uint8List with a
/// given [length].
Uint8List toBigEndianFromDER(Uint8List der, int length)
  => padZeroBigEndian(der.sublist(der[0] == 0 ? 1 : 0), length);

