import 'dart:typed_data';
import 'varuint.dart' as varuint;

class BytesReaderWriter {
  int offset;
  final ByteData bytes;

  BytesReaderWriter(Uint8List bytes, [this.offset = 0])
      : bytes = bytes.buffer.asByteData();

  int readUInt8() => bytes.getUint8(offset++);

  int readUInt32() {
    final i = bytes.getUint32(offset, Endian.little);
    offset += 4;
    return i;
  }

  int readInt32() {
    final i = bytes.getInt32(offset, Endian.little);
    offset += 4;
    return i;
  }

  /// Returns a BigInt to ensure that a full 64 unsigned bits are represented.
  /// Web targets do not have enough precision and native ints are signed.
  BigInt readUInt64() {
    return BigInt.from(readUInt32()) | (BigInt.from(readUInt32()) << 32);
  }

  Uint8List readSlice(int n) {
    offset += n;
    return Uint8List.fromList(bytes.buffer.asUint8List(offset - n, n));
  }

  int readVarInt() {
    final vi = varuint.decode(bytes.buffer.asUint8List(), offset);
    offset += varuint.encodingLength(vi);
    return vi;
  }

  Uint8List readVarSlice() {
    return readSlice(readVarInt());
  }

  List<Uint8List> readVector() {
    var count = readVarInt();
    List<Uint8List> vector = [];
    for (var i = 0; i < count; ++i) {
      vector.add(readVarSlice());
    }
    return vector;
  }

  writeUInt8(int i) {
    bytes.setUint8(offset, i);
    offset++;
  }

  writeUInt32(int i) {
    bytes.setUint32(offset, i, Endian.little);
    offset += 4;
  }

  writeInt32(int i) {
    bytes.setInt32(offset, i, Endian.little);
    offset += 4;
  }

  writeUInt64(BigInt i) {
    writeUInt32(i.toUnsigned(32).toInt());
    writeUInt32((i >> 32).toUnsigned(32).toInt());
  }

  writeSlice(List<int> slice) {
    bytes.buffer.asUint8List().setAll(offset, slice);
    offset += slice.length;
  }

  writeVarInt(int i) {
    varuint.encode(i, bytes.buffer.asUint8List(), offset);
    offset += varuint.encodingLength(i);
  }

  writeVarSlice(Uint8List slice) {
    writeVarInt(slice.length);
    writeSlice(slice);
  }

  writeVector(List<Uint8List> vector) {
    writeVarInt(vector.length);
    for (final bytes in vector) {
      writeVarSlice(bytes);
    }
  }

  bool get atEnd => offset == bytes.lengthInBytes;
}
