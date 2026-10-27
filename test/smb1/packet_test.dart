import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:mornye/services/smb/v1/commands.dart';
import 'package:mornye/services/smb/v1/packet.dart';
import 'package:mornye/services/smb/v1/status.dart';

void main() {
  group('SMB1 Packet codec', () {
    test('encode and decode roundtrip preserves fields', () {
      final packet = Smb1Packet(
        command: Smb1Packet.cmdNegotiate,
        status: NtStatus.success,
        flags:
            Smb1Packet.flagCaseInsensitive | Smb1Packet.flagCanonicalizedPaths,
        flags2: Smb1Packet.flag2Unicode | Smb1Packet.flag2NtStatus,
        tid: 10,
        pidLow: 1234,
        uid: 42,
        mid: 99,
        words: [1, 2, 3],
        bytes: Uint8List.fromList([0xAA, 0xBB, 0xCC]),
      );

      final encoded = packet.encode();
      expect(encoded.take(4), [0xFF, 0x53, 0x4D, 0x42]); // 0xFF 'S' 'M' 'B'

      final decoded = Smb1Packet.decode(encoded);
      expect(decoded.command, Smb1Packet.cmdNegotiate);
      expect(decoded.status, NtStatus.success);
      expect(decoded.tid, 10);
      expect(decoded.pidLow, 1234);
      expect(decoded.uid, 42);
      expect(decoded.mid, 99);
      expect(decoded.words, [1, 2, 3]);
      expect(decoded.bytes, [0xAA, 0xBB, 0xCC]);
    });

    test('negotiate request contains only NT LM 0.12 dialect', () {
      final req = Smb1Commands.createNegotiateRequest();
      final encoded = req.encode();
      expect(encoded.take(4), [0xFF, 0x53, 0x4D, 0x42]);
      expect(req.command, Smb1Packet.cmdNegotiate);
      expect(req.bytes.first, 0x02);
      final dialectStr = ascii.decode(
        req.bytes.sublist(1, req.bytes.length - 1),
      );
      expect(dialectStr, 'NT LM 0.12');
    });

    test('NTSTATUS status codes mapping', () {
      expect(NtStatus.toSmbErrorType(NtStatus.logonFailure), isA<Object>());
      expect(NtStatus.describe(NtStatus.accessDenied), 'STATUS_ACCESS_DENIED');
      expect(
        NtStatus.describe(NtStatus.objectNameNotFound),
        'STATUS_OBJECT_NAME_NOT_FOUND',
      );
    });
  });
}
