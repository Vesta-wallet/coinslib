import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:coinslib/src/utils/serialisation.dart';

main() {
  group('BytesReaderWriter', () {
    final bi = BigInt.parse("0x0123456789ABCDEF");

    test('readUInt64', () {
      final reader = BytesReaderWriter(
        Uint8List.fromList([0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]),
      );
      expect(reader.readUInt64(), bi);
    });

    test('writeUInt64', () {
      final writer = BytesReaderWriter(Uint8List(8));
      writer.writeUInt64(bi);
      writer.offset = 0;
      expect(writer.readUInt64(), bi);
    });
  });
}
