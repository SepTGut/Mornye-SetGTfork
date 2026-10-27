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

    test(
      'Type 3 authentication message generation from mock Type 2 challenge',
      () {
        // Mock 48-byte Type 2 Challenge message
        final type2 = Uint8List(48);
        type2.setRange(0, 8, 'NTLMSSP\x00'.codeUnits);
        final bd = ByteData.sublistView(type2);
        bd.setUint32(8, 2, Endian.little); // Type: 2
        bd.setUint32(20, 0x00088205, Endian.little); // Flags
        // 8-byte server challenge at offset 24
        type2.setRange(24, 32, [
          0x01,
          0x02,
          0x03,
          0x04,
          0x05,
          0x06,
          0x07,
          0x08,
        ]);

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
      },
    );

    test('Type 3 anonymous authentication message formatting', () {
      final type2 = Uint8List(48);
      type2.setRange(0, 8, 'NTLMSSP\x00'.codeUnits);
      final bd = ByteData.sublistView(type2);
      bd.setUint32(8, 2, Endian.little);
      bd.setUint32(20, 0x00088205, Endian.little);
      type2.setRange(24, 32, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

      final result = NtlmContext.createType3Message(
        type2Message: type2,
        username: '',
        password: '',
        domain: '',
      );

      final msg = result.authenticateMessage;
      expect(msg.length, 64);
      expect(ascii.decode(msg.sublist(0, 8)), 'NTLMSSP\x00');
      final bd3 = ByteData.sublistView(msg);
      expect(bd3.getUint32(8, Endian.little), 3); // Message Type: 3
      // All response and name buffers must have length 0
      expect(bd3.getUint16(12, Endian.little), 0); // LM length
      expect(bd3.getUint16(20, Endian.little), 0); // NT length
      expect(bd3.getUint16(28, Endian.little), 0); // Domain length
      expect(bd3.getUint16(36, Endian.little), 0); // User length
      expect(bd3.getUint16(44, Endian.little), 0); // Workstation length
      // Flags must include flagNegotiateAnonymous (0x00000800)
      final flags = bd3.getUint32(60, Endian.little);
      expect(flags & NtlmContext.flagNegotiateAnonymous, isNot(0));
      // SessionBaseKey must be 16 zero bytes
      expect(result.sessionBaseKey, Uint8List(16));
    });
  });
}
