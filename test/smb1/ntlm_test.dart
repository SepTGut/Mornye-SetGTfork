import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:mornye/services/smb/v1/ntlm.dart';

void main() {
  group('NTLMSSP / NTLMv2 module', () {
    test('Type 1 negotiate message formatting', () {
      final msg = NtlmContext.createType1Message(domain: 'WORKGROUP');
      expect(msg.length, greaterThanOrEqualTo(40));
      expect(ascii.decode(msg.sublist(0, 8)), 'NTLMSSP\x00');
      final bd = ByteData.sublistView(msg);
      expect(bd.getUint32(8, Endian.little), 1); // Message Type: 1
    });

    test('Type 3 authentication message generation from mock Type 2 challenge', () {
      // Mock 48-byte Type 2 Challenge message
      final type2 = Uint8List(48);
      type2.setRange(0, 8, 'NTLMSSP\x00'.codeUnits);
      final bd = ByteData.sublistView(type2);
      bd.setUint32(8, 2, Endian.little); // Type: 2
      bd.setUint32(20, 0x00088205, Endian.little); // Flags
      // 8-byte server challenge at offset 24
      type2.setRange(24, 32, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

      final result = NtlmContext.createType3Message(
        type2Message: type2,
        username: 'User',
        password: 'Password',
        domain: 'WORKGROUP',
      );

      final msg = result.authenticateMessage;
      expect(ascii.decode(msg.sublist(0, 8)), 'NTLMSSP\x00');
      final bd3 = ByteData.sublistView(msg);
      expect(bd3.getUint32(8, Endian.little), 3); // Type: 3
      expect(result.sessionBaseKey.length, 16);
    });
  });
}
