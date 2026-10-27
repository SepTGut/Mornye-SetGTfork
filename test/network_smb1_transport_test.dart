import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:mornye/services/smb/v1/smb1_client.dart';

void main() {
  test(
    'SMB1 client negotiates strictly NT LM 0.12 dialect with 0xFF SMB header',
    () async {
      final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final received = Completer<List<int>>();

      final subscription = server.listen((socket) {
        final bytes = <int>[];
        socket.listen((chunk) {
          bytes.addAll(chunk);
          if (bytes.length < 4) return;
          final size = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
          if (bytes.length < size + 4 || received.isCompleted) return;
          received.complete(bytes.sublist(4, size + 4));
          socket.destroy();
        });
      });

      try {
        final attempt = Smb1Client.connect(
          Uri.parse('smb://127.0.0.1:${server.port}/MUSIC'),
          username: 'test',
          password: 'secret',
          domain: '',
          timeout: const Duration(seconds: 2),
        );
        final failure = expectLater(attempt, throwsA(isA<Exception>()));

        final packet = await received.future.timeout(
          const Duration(seconds: 5),
        );

        // Header magic must be SMB1 magic: [0xFF, 'S', 'M', 'B']
        expect(packet.take(4), [0xFF, 0x53, 0x4D, 0x42]);

        // Command must be 0x72 (SMB_COM_NEGOTIATE)
        expect(packet[4], 0x72);

        // Dialect string in data bytes must be strictly NT LM 0.12
        final wordCount = packet[32];
        final wordsEnd = 33 + (wordCount * 2);
        final byteData = packet.sublist(wordsEnd + 2);

        expect(byteData.first, 0x02);
        final nullTerm = byteData.indexOf(0, 1);
        final dialect = ascii.decode(byteData.sublist(1, nullTerm));
        expect(dialect, 'NT LM 0.12');

        await failure;
      } finally {
        await subscription.cancel();
        await server.close();
      }
    },
  );
}
