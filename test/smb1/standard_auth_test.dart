import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:mornye/services/smb/v1/commands.dart';
import 'package:mornye/services/smb/v1/packet.dart';

void main() {
  group('Standard SMB1 Session Setup (Non-Extended Security)', () {
    test('createStandardSessionSetupRequest format with credentials', () {
      final challenge = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final packet = Smb1Commands.createStandardSessionSetupRequest(
        username: 'alice',
        password: 'password123',
        domain: 'WORKGROUP',
        serverChallenge: challenge,
      );

      expect(packet.command, Smb1Packet.cmdSessionSetupAndX);
      expect(packet.words.length, 13);
      // flags2 must NOT have extended security
      expect(packet.flags2 & Smb1Packet.flag2ExtendedSecurity, 0);
      expect(packet.flags2 & Smb1Packet.flag2Unicode, isNot(0));

      // Word 7 is CaseInsensitivePasswordLength (24)
      expect(packet.words[7], 24);
      // Word 8 is CaseSensitivePasswordLength (24)
      expect(packet.words[8], 24);

      // Verify packet can be encoded and decoded
      final encoded = packet.encode();
      final decoded = Smb1Packet.decode(encoded);
      expect(decoded.command, Smb1Packet.cmdSessionSetupAndX);
      expect(decoded.words.length, 13);
    });

    test('createStandardSessionSetupRequest format anonymous / guest', () {
      final challenge = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final packet = Smb1Commands.createStandardSessionSetupRequest(
        username: '',
        password: '',
        domain: '',
        serverChallenge: challenge,
      );

      expect(packet.command, Smb1Packet.cmdSessionSetupAndX);
      expect(packet.words.length, 13);
      expect(packet.flags2 & Smb1Packet.flag2ExtendedSecurity, 0);

      // Anonymous passwords should have length 0
      expect(packet.words[7], 0);
      expect(packet.words[8], 0);

      final encoded = packet.encode();
      final decoded = Smb1Packet.decode(encoded);
      expect(decoded.command, Smb1Packet.cmdSessionSetupAndX);
      expect(decoded.words.length, 13);
    });
  });
}
