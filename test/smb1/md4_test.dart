import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:mornye/services/smb/v1/md4.dart';

void main() {
  group('MD4 RFC 1320 test vectors', () {
    String hex(Uint8List bytes) =>
        bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    test('empty string', () {
      final digest = Md4.digest(Uint8List(0));
      expect(hex(digest), '31d6cfe0d16ae931b73c59d7e0c089c0');
    });

    test('"a"', () {
      final digest = Md4.digest(Uint8List.fromList(ascii.encode('a')));
      expect(hex(digest), 'bde52cb31de33e46245e05fbdbd6fb24');
    });

    test('"abc"', () {
      final digest = Md4.digest(Uint8List.fromList(ascii.encode('abc')));
      expect(hex(digest), 'a4480131aaf21d82f6ecbea704a7e776');
    });

    test('"message digest"', () {
      final digest = Md4.digest(
        Uint8List.fromList(ascii.encode('message digest')),
      );
      expect(hex(digest), 'd9130a8164549fe818874806e1c7014b');
    });

    test('"abcdefghijklmnopqrstuvwxyz"', () {
      final digest = Md4.digest(
        Uint8List.fromList(ascii.encode('abcdefghijklmnopqrstuvwxyz')),
      );
      expect(hex(digest), 'd79e1c308aa5bbcdeea8ed63df412da9');
    });

    test('NT password hash for "Secr3t"', () {
      // UTF-16LE encoding of "Secr3t"
      final units = 'Secr3t'.codeUnits;
      final bytes = Uint8List(units.length * 2);
      final bd = ByteData.sublistView(bytes);
      for (var i = 0; i < units.length; i++) {
        bd.setUint16(i * 2, units[i], Endian.little);
      }
      final ntHash = Md4.digest(bytes);
      // Valid NT hash for "Secr3t" is 209c6174da490caeb422f3fa5a7ae634
      expect(hex(ntHash), '209c6174da490caeb422f3fa5a7ae634');
    });
  });
}
