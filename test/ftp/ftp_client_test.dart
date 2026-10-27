import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:mornye/services/ftp/ftp_client.dart';
import 'package:mornye/services/smb/smb_client.dart';

class MockFtpServer {
  late ServerSocket _server;
  late int port;
  final Map<String, Uint8List> files = {};
  final Set<String> directories = {'/', '/Music', '/Music/Albums'};
  bool failAuth = false;
  bool usePasvOnly = false;
  bool returnFakePasvIp = false;
  bool denyDelete = false;

  ServerSocket? _dataServer;
  Completer<Socket>? _dataSocketCompleter;
  int _pendingRest = 0;
  String? _rnfrPath;

  Future<void> start() async {
    _server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = _server.port;
    _server.listen(_handleControl);
  }

  Future<void> stop() async {
    await _dataServer?.close();
    await _server.close();
  }

  void _handleControl(Socket socket) {
    void reply(String line) {
      socket.write('$line\r\n');
    }

    reply('220 Mock FTP ready');

    socket
        .cast<List<int>>()
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) async {
          final trimmed = line.trim();
          if (trimmed.isEmpty) return;

          final spaceIdx = trimmed.indexOf(' ');
          final cmd = (spaceIdx < 0 ? trimmed : trimmed.substring(0, spaceIdx))
              .toUpperCase();
          final arg = spaceIdx < 0
              ? ''
              : trimmed.substring(spaceIdx + 1).trim();

          switch (cmd) {
            case 'USER':
              reply('331 Password required');
              break;
            case 'PASS':
              if (failAuth) {
                reply('530 Login incorrect');
              } else {
                reply('230 User logged in');
              }
              break;
            case 'FEAT':
              socket.write(
                '211-Features:\r\n MLSD\r\n REST STREAM\r\n SIZE\r\n MDTM\r\n211 End\r\n',
              );
              await socket.flush();
              break;
            case 'TYPE':
              reply('200 Type set to $arg');
              break;
            case 'EPSV':
              if (usePasvOnly) {
                reply('500 EPSV not understood');
              } else {
                _dataServer = await ServerSocket.bind(
                  InternetAddress.loopbackIPv4,
                  0,
                );
                final completer = Completer<Socket>();
                _dataSocketCompleter = completer;
                _dataServer!.listen((s) {
                  if (!completer.isCompleted) completer.complete(s);
                });
                reply(
                  '229 Entering Extended Passive Mode (|||${_dataServer!.port}|)',
                );
              }
              break;
            case 'PASV':
              _dataServer = await ServerSocket.bind(
                InternetAddress.loopbackIPv4,
                0,
              );
              final completer = Completer<Socket>();
              _dataSocketCompleter = completer;
              _dataServer!.listen((s) {
                if (!completer.isCompleted) completer.complete(s);
              });
              final p1 = _dataServer!.port ~/ 256;
              final p2 = _dataServer!.port % 256;
              final ip = returnFakePasvIp ? '10,99,99,99' : '127,0,0,1';
              reply('227 Entering Passive Mode ($ip,$p1,$p2)');
              break;
            case 'MLSD':
              reply('150 Opening data connection');
              final dataSocket = await _dataSocketCompleter!.future;
              final normalizedArg = arg.replaceAll('\\', '/');
              final targetDir = normalizedArg.isEmpty || normalizedArg == '/'
                  ? '/'
                  : (normalizedArg.endsWith('/')
                        ? normalizedArg
                        : '$normalizedArg/');
              final buffer = StringBuffer();
              buffer.write('type=cdir; .\r\n');
              buffer.write('type=pdir; ..\r\n');

              for (final dir in directories) {
                if (dir == targetDir || dir == '/') continue;
                final parent = dir.substring(0, dir.lastIndexOf('/') + 1);
                if (parent == targetDir) {
                  final name = dir.substring(dir.lastIndexOf('/') + 1);
                  buffer.write('type=dir; $name\r\n');
                }
              }
              for (final file in files.keys) {
                final parent = file.substring(0, file.lastIndexOf('/') + 1);
                if (parent == targetDir) {
                  final name = file.substring(file.lastIndexOf('/') + 1);
                  buffer.write(
                    'type=file;size=${files[file]!.length};modify=20261027120000; $name\r\n',
                  );
                }
              }
              dataSocket.write(buffer.toString());
              await dataSocket.flush();
              await dataSocket.close();
              await _dataServer?.close();
              _dataServer = null;
              reply('226 Transfer complete');
              break;
            case 'SIZE':
              final normalized = arg.startsWith('/') ? arg : '/$arg';
              if (files.containsKey(normalized)) {
                reply('213 ${files[normalized]!.length}');
              } else {
                reply('550 Not a regular file');
              }
              break;
            case 'MDTM':
              final normalized = arg.startsWith('/') ? arg : '/$arg';
              if (files.containsKey(normalized)) {
                reply('213 20261027120000');
              } else {
                reply('550 File not found');
              }
              break;
            case 'CWD':
              final normalized = arg.endsWith('/') ? arg : '$arg/';
              final withSlash = arg.startsWith('/') ? arg : '/$arg';
              final withSlashEnding = normalized.startsWith('/')
                  ? normalized
                  : '/$normalized';
              if (directories.contains(arg) ||
                  directories.contains(normalized) ||
                  directories.contains(withSlash) ||
                  directories.contains(withSlashEnding)) {
                reply('250 Directory changed');
              } else {
                reply('550 Directory not found');
              }
              break;
            case 'PWD':
              reply('257 "/" is current directory');
              break;
            case 'REST':
              _pendingRest = int.tryParse(arg) ?? 0;
              reply('350 Restarting at $_pendingRest');
              break;
            case 'RETR':
              final normalized = arg.startsWith('/') ? arg : '/$arg';
              if (!files.containsKey(normalized)) {
                reply('550 File not found');
                break;
              }
              reply('150 Opening data connection');
              final dataSocket = await _dataSocketCompleter!.future;
              final data = files[normalized]!;
              if (_pendingRest < data.length) {
                dataSocket.add(data.sublist(_pendingRest));
              }
              _pendingRest = 0;
              await dataSocket.flush();
              await dataSocket.close();
              await _dataServer?.close();
              _dataServer = null;
              reply('226 Transfer complete');
              break;
            case 'STOR':
              reply('150 Opening data connection');
              final dataSocket = await _dataSocketCompleter!.future;
              final bytes = BytesBuilder();
              await for (final chunk in dataSocket) {
                bytes.add(chunk);
              }
              final normalized = arg.startsWith('/') ? arg : '/$arg';
              files[normalized] = bytes.takeBytes();
              await dataSocket.close();
              await _dataServer?.close();
              _dataServer = null;
              reply('226 Transfer complete');
              break;
            case 'RNFR':
              final normalized = arg.startsWith('/') ? arg : '/$arg';
              if (files.containsKey(normalized)) {
                _rnfrPath = normalized;
                reply('350 Ready for destination');
              } else {
                reply('550 File not found');
              }
              break;
            case 'RNTO':
              final normalized = arg.startsWith('/') ? arg : '/$arg';
              if (_rnfrPath != null && files.containsKey(_rnfrPath)) {
                files[normalized] = files.remove(_rnfrPath)!;
                _rnfrPath = null;
                reply('250 Rename successful');
              } else {
                reply('550 Rename failed');
              }
              break;
            case 'DELE':
              final normalized = arg.startsWith('/') ? arg : '/$arg';
              if (denyDelete) {
                reply('550 Permission denied');
              } else if (files.containsKey(normalized)) {
                files.remove(normalized);
                reply('250 File deleted');
              } else {
                reply('550 File not found');
              }
              break;
            case 'MKD':
              final normalized = arg.startsWith('/') ? arg : '/$arg';
              directories.add(normalized);
              reply('257 "$normalized" created');
              break;
            case 'QUIT':
              reply('221 Goodbye');
              break;
            default:
              reply('502 Command not implemented');
              break;
          }
        });
  }
}

void main() {
  late MockFtpServer server;

  setUp(() async {
    server = MockFtpServer();
    await server.start();
  });

  tearDown(() async {
    await server.stop();
  });

  test('FtpClient connects, authenticates and checks features', () async {
    final client = await FtpClient.connect(
      Uri.parse('ftp://127.0.0.1:${server.port}/Music/'),
      username: 'user',
      password: 'password',
    );
    expect(client.path, 'Music');
    await client.close();
  });

  test('FtpClient throws SmbException with auth on bad credentials', () async {
    server.failAuth = true;
    expect(
      () => FtpClient.connect(
        Uri.parse('ftp://127.0.0.1:${server.port}/Music/'),
        username: 'bad',
        password: 'bad',
      ),
      throwsA(
        isA<SmbException>().having((e) => e.type, 'type', SmbErrorType.auth),
      ),
    );
  });

  test('FtpClient lists files and directories with MLSD', () async {
    server.files['/Music/track.mp3'] = Uint8List.fromList([1, 2, 3]);

    final client = await FtpClient.connect(
      Uri.parse('ftp://127.0.0.1:${server.port}/Music/'),
    );
    final entries = await client.list();
    expect(entries.length, 2);

    final dir = entries.firstWhere((e) => e.isDirectory);
    expect(dir.name, 'Albums');

    final file = entries.firstWhere((e) => !e.isDirectory);
    expect(file.name, 'track.mp3');
    expect(file.size, 3);
    await client.close();
  });

  test(
    'FtpClient stat returns correct attributes for files and directories',
    () async {
      server.files['/Music/track.flac'] = Uint8List(1024);

      final fileClient = await FtpClient.connect(
        Uri.parse('ftp://127.0.0.1:${server.port}/Music/track.flac'),
      );
      final fileStat = await fileClient.stat();
      expect(fileStat.isFile, isTrue);
      expect(fileStat.isDirectory, isFalse);
      expect(fileStat.size, 1024);
      await fileClient.close();

      final dirClient = await FtpClient.connect(
        Uri.parse('ftp://127.0.0.1:${server.port}/Music/Albums'),
      );
      final dirStat = await dirClient.stat();
      expect(dirStat.isFile, isFalse);
      expect(dirStat.isDirectory, isTrue);
      await dirClient.close();
    },
  );

  test('FtpClient reads full file and byte range with REST', () async {
    final payload = Uint8List.fromList(List.generate(100, (i) => i));
    server.files['/Music/test.bin'] = payload;

    // Full read (0 to 100)
    final client1 = await FtpClient.connect(
      Uri.parse('ftp://127.0.0.1:${server.port}/Music/test.bin'),
    );
    final fullChunks = await client1.read(0, 100).toList();
    final fullBytes = Uint8List.fromList(fullChunks.expand((c) => c).toList());
    expect(fullBytes, payload);
    await client1.close();

    // Partial read from offset 50 to 100
    final client2 = await FtpClient.connect(
      Uri.parse('ftp://127.0.0.1:${server.port}/Music/test.bin'),
    );
    final partialChunks = await client2.read(50, 100).toList();
    final partialBytes = Uint8List.fromList(
      partialChunks.expand((c) => c).toList(),
    );
    expect(partialBytes, payload.sublist(50));
    await client2.close();
  });

  test(
    'FtpClient uploads file and avoids overwriting rename collisions',
    () async {
      final tempDir = Directory.systemTemp.createTempSync('ftp_test_');
      try {
        final uploadFile = File('${tempDir.path}/upload.bin');
        final uploadData = Uint8List.fromList([10, 20, 30, 40]);
        await uploadFile.writeAsBytes(uploadData);

        final client = await FtpClient.connect(
          Uri.parse('ftp://127.0.0.1:${server.port}/Music/'),
        );

        await client.upload(
          'new.tmp',
          uploadFile,
          checkpoint: () {},
          progress: (_) {},
        );
        expect(server.files['/Music/new.tmp'], uploadData);

        // Rename to destination
        await client.rename('new.tmp', 'new.flac');
        expect(server.files['/Music/new.flac'], uploadData);
        expect(server.files.containsKey('/Music/new.tmp'), isFalse);

        // Second upload trying to rename to existing 'new.flac' should throw invalidParam
        await client.upload(
          'collision.tmp',
          uploadFile,
          checkpoint: () {},
          progress: (_) {},
        );
        await expectLater(
          () => client.rename('collision.tmp', 'new.flac'),
          throwsA(
            isA<SmbException>().having(
              (e) => e.type,
              'type',
              SmbErrorType.invalidParam,
            ),
          ),
        );

        await client.close();
      } finally {
        tempDir.deleteSync(recursive: true);
      }
    },
  );

  test('FtpClient delete succeeds or handles safe 550', () async {
    server.files['/Music/delete_me.mp3'] = Uint8List(10);

    final client = await FtpClient.connect(
      Uri.parse('ftp://127.0.0.1:${server.port}/Music/'),
    );

    await client.delete('delete_me.mp3');
    expect(server.files.containsKey('/Music/delete_me.mp3'), isFalse);

    // Deleting non-existent file throws fileNotFound
    await expectLater(
      () => client.delete('already_gone.mp3'),
      throwsA(
        isA<SmbException>().having(
          (e) => e.type,
          'type',
          SmbErrorType.fileNotFound,
        ),
      ),
    );

    // Deleting when server returns 550 but file is still present throws accessDenied
    server.files['/Music/locked.mp3'] = Uint8List(10);
    server.denyDelete = true;
    await expectLater(
      () => client.delete('locked.mp3'),
      throwsA(
        isA<SmbException>().having(
          (e) => e.type,
          'type',
          SmbErrorType.accessDenied,
        ),
      ),
    );

    await client.close();
  });

  test('FtpClient pins control socket IP for PASV data connections', () async {
    server.usePasvOnly = true;
    server.returnFakePasvIp = true; // Returns 10.99.99.99
    server.files['/Music/pasv.mp3'] = Uint8List.fromList([42]);

    // Client connects to 127.0.0.1. PASV will reply with 10.99.99.99, but client
    // pins to 127.0.0.1 and successfully transfers data!
    final client = await FtpClient.connect(
      Uri.parse('ftp://127.0.0.1:${server.port}/Music/pasv.mp3'),
    );
    final chunks = await client.read(0, 1).toList();
    expect(chunks.first, [42]);
    await client.close();
  });
}
