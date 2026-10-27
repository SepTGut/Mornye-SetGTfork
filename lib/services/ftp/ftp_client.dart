import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:mornye/services/ftp/ftp_listing.dart';
import 'package:mornye/services/smb/smb_client.dart';
import 'package:synchronized/synchronized.dart';

class FtpResponse {
  const FtpResponse(this.code, this.lines, this.message);
  final int code;
  final List<String> lines;
  final String message;

  bool get isSuccess => code >= 200 && code < 300;
  bool get isPositiveIntermediate => code >= 300 && code < 400;

  @override
  String toString() => '$code $message';
}

class FtpClient implements SmbClient {
  FtpClient._(this._socket, this.path, {required Duration timeout})
    : _timeout = timeout {
    _socketSub = _socket.listen(
      _onData,
      onError: (Object err) {
        _failPending(err);
      },
      onDone: () {
        _failPending(const SocketException('FTP control connection closed'));
      },
    );
  }

  final Socket _socket;
  late final StreamSubscription<Uint8List> _socketSub;
  final Duration _timeout;
  final _lock = Lock();
  bool _closed = false;

  @override
  final String path;

  final _receiveBuffer = StringBuffer();
  Completer<FtpResponse>? _pendingResponse;
  final _currentLines = <String>[];

  static Future<FtpClient> connect(
    Uri target, {
    String username = '',
    String password = '',
    Duration timeout = const Duration(seconds: 15),
  }) async {
    final port = target.hasPort ? target.port : 21;
    // ignore: close_sinks
    final socket = await Socket.connect(target.host, port, timeout: timeout);

    final client = FtpClient._(
      socket,
      target.pathSegments.where((s) => s.isNotEmpty).join('/'),
      timeout: timeout,
    );

    try {
      // 1. Initial banner (220)
      final banner = await client._readResponse().timeout(timeout);
      if (banner.code != 220) {
        throw SmbException(
          'Unexpected FTP banner: ${banner.message}',
          SmbErrorType.connection,
        );
      }

      // 2. Authentication
      final user = username.trim().isEmpty ? 'anonymous' : username.trim();
      final userResp = await client._sendCommand('USER $user');
      if (userResp.code == 331) {
        final pass = username.trim().isEmpty ? 'anonymous@' : password;
        final passResp = await client._sendCommand('PASS $pass');
        if (passResp.code != 230) {
          throw SmbException(
            'FTP login failed: ${passResp.message}',
            SmbErrorType.auth,
          );
        }
      } else if (userResp.code != 230) {
        throw SmbException(
          'FTP user rejected: ${userResp.message}',
          SmbErrorType.auth,
        );
      }

      // 3. Optional FEAT and UTF-8 enablement
      try {
        await client._sendCommand('FEAT');
      } catch (_) {}

      try {
        await client._sendCommand('OPTS UTF8 ON');
      } catch (_) {}

      // 4. Binary mode
      final typeResp = await client._sendCommand('TYPE I');
      if (typeResp.code != 200) {
        throw SmbException(
          'Failed to set binary transfer mode: ${typeResp.message}',
          SmbErrorType.incompatible,
        );
      }

      return client;
    } catch (_) {
      await client.close();
      rethrow;
    }
  }

  void _onData(Uint8List data) {
    final text = utf8.decode(data, allowMalformed: true);
    _receiveBuffer.write(text);

    while (true) {
      final content = _receiveBuffer.toString();
      final newlineIdx = content.indexOf('\n');
      if (newlineIdx < 0) break;

      var line = content.substring(0, newlineIdx);
      if (line.endsWith('\r')) {
        line = line.substring(0, line.length - 1);
      }

      final remaining = content.substring(newlineIdx + 1);
      _receiveBuffer.clear();
      _receiveBuffer.write(remaining);

      _processLine(line);
    }
  }

  void _processLine(String line) {
    _currentLines.add(line);

    // RFC 959: A single line response or last line of multi-line is "XYZ <message>"
    if (line.length >= 3 && int.tryParse(line.substring(0, 3)) != null) {
      if (line.length == 3 || line[3] == ' ') {
        final code = int.parse(line.substring(0, 3));
        final msg = line.length > 4 ? line.substring(4) : '';
        final resp = FtpResponse(code, List.unmodifiable(_currentLines), msg);
        _currentLines.clear();

        final completer = _pendingResponse;
        _pendingResponse = null;
        completer?.complete(resp);
      }
    }
  }

  void _failPending(Object error) {
    final completer = _pendingResponse;
    _pendingResponse = null;
    if (completer != null && !completer.isCompleted) {
      completer.completeError(error);
    }
  }

  Future<FtpResponse> _readResponse() {
    if (_pendingResponse != null) {
      throw StateError('Concurrent FTP response read');
    }
    final completer = Completer<FtpResponse>();
    _pendingResponse = completer;
    return completer.future;
  }

  Future<FtpResponse> _sendCommand(String command) =>
      _lock.synchronized(() async {
        if (_closed) {
          throw const SmbException('Client is closed', SmbErrorType.connection);
        }
        _socket.write('$command\r\n');
        await _socket.flush();
        return await _readResponse().timeout(_timeout);
      });

  Future<Socket> _openDataSocket() async {
    // 1. Try EPSV
    var epsvResp = await _sendCommand('EPSV');
    int? port;
    if (epsvResp.code == 229) {
      try {
        port = FtpListingParser.parseEpsv(epsvResp.message);
      } catch (_) {}
    }

    // 2. Fall back to PASV if EPSV failed or unsupported
    if (port == null) {
      final pasvResp = await _sendCommand('PASV');
      if (pasvResp.code != 227) {
        throw SmbException(
          'Passive mode rejected: ${pasvResp.message}',
          SmbErrorType.connection,
        );
      }
      port = FtpListingParser.parsePasv(pasvResp.message);
    }

    // Security & NAT rule: Pin data socket host to the control connection's remote IP!
    final host = _socket.remoteAddress.address;
    return await Socket.connect(host, port, timeout: _timeout);
  }

  String _clean(String p) {
    var s = p.replaceAll('\\', '/');
    while (s.startsWith('/')) {
      s = s.substring(1);
    }
    while (s.endsWith('/') && s.isNotEmpty) {
      s = s.substring(0, s.length - 1);
    }
    return s;
  }

  String _resolve(String relative) {
    final cleanRel = _clean(relative);
    final cleanBase = _clean(path);
    if (cleanRel.isEmpty) return cleanBase;
    if (cleanBase.isEmpty) return cleanRel;
    if (cleanRel == cleanBase || cleanRel.startsWith('$cleanBase/')) {
      return cleanRel;
    }
    return '$cleanBase/$cleanRel';
  }

  String _toFtpPath(String p) {
    final c = _clean(p);
    return c.isEmpty ? '/' : '/$c';
  }

  @override
  Future<List<SmbEntry>> list() async {
    final targetPath = _toFtpPath(path);
    final dataSocket = await _openDataSocket();

    try {
      final cmd = targetPath == '/' ? 'MLSD' : 'MLSD $targetPath';
      var resp = await _sendCommand(cmd);

      var usedMlsd = true;
      if (resp.code != 150 && resp.code != 125) {
        // Try fallback to LIST -a
        await dataSocket.close();
        final listDataSocket = await _openDataSocket();
        final listCmd = targetPath == '/' ? 'LIST -a' : 'LIST -a $targetPath';
        final listResp = await _sendCommand(listCmd);
        if (listResp.code != 150 && listResp.code != 125) {
          await listDataSocket.close();
          throw SmbException(
            'Failed to list directory "$path": ${listResp.message}',
            _mapFtpError(listResp.code),
          );
        }
        return await _readListingData(listDataSocket, usedMlsd: false);
      }

      return await _readListingData(dataSocket, usedMlsd: usedMlsd);
    } catch (_) {
      try {
        await dataSocket.close();
      } catch (_) {}
      rethrow;
    }
  }

  Future<List<SmbEntry>> _readListingData(
    Socket dataSocket, {
    required bool usedMlsd,
  }) async {
    final chunks = <int>[];
    await for (final chunk in dataSocket) {
      chunks.addAll(chunk);
    }
    final rawText = utf8.decode(chunks, allowMalformed: true);
    final lines = rawText.split(RegExp(r'\r?\n'));

    // Await 226 transfer complete on control channel
    final completeResp = await _readResponse().timeout(_timeout);
    if (completeResp.code != 226 && completeResp.code != 250) {
      throw SmbException(
        'Listing data transfer incomplete: ${completeResp.message}',
        SmbErrorType.connection,
      );
    }

    final items = usedMlsd
        ? FtpListingParser.parseMlsd(lines)
        : FtpListingParser.parseList(lines);

    return [
      for (final item in items)
        if (item.name != '.' && item.name != '..') item.toSmbEntry(),
    ];
  }

  @override
  Future<SmbStat> stat() async {
    final targetPath = _toFtpPath(path);
    if (targetPath == '/') {
      return SmbStat(
        isFile: false,
        isDirectory: true,
        size: 0,
        modified: DateTime.now().toUtc(),
      );
    }

    // 1. Try MLST
    final mlstResp = await _sendCommand('MLST $targetPath');
    if (mlstResp.code == 250) {
      final items = FtpListingParser.parseMlsd(mlstResp.lines);
      if (items.isNotEmpty) {
        final item = items.first;
        return SmbStat(
          isFile: !item.isDirectory,
          isDirectory: item.isDirectory,
          size: item.size,
          modified: DateTime.fromMillisecondsSinceEpoch(
            item.modifiedTime > 0
                ? item.modifiedTime
                : DateTime.now().millisecondsSinceEpoch,
            isUtc: true,
          ),
        );
      }
    }

    // 2. Try SIZE (works for files)
    final sizeResp = await _sendCommand('SIZE $targetPath');
    if (sizeResp.code == 213) {
      final size = int.tryParse(sizeResp.message.trim()) ?? 0;
      var modifiedMs = 0;
      final mdtmResp = await _sendCommand('MDTM $targetPath');
      if (mdtmResp.code == 213) {
        final raw = mdtmResp.message.trim();
        if (raw.length >= 14) {
          try {
            final dt = DateTime.utc(
              int.parse(raw.substring(0, 4)),
              int.parse(raw.substring(4, 6)),
              int.parse(raw.substring(6, 8)),
              int.parse(raw.substring(8, 10)),
              int.parse(raw.substring(10, 12)),
              int.parse(raw.substring(12, 14)),
            );
            modifiedMs = dt.millisecondsSinceEpoch;
          } catch (_) {}
        }
      }
      return SmbStat(
        isFile: true,
        isDirectory: false,
        size: size,
        modified: DateTime.fromMillisecondsSinceEpoch(
          modifiedMs > 0 ? modifiedMs : DateTime.now().millisecondsSinceEpoch,
          isUtc: true,
        ),
      );
    }

    // 3. Try directory check via CWD
    final pwdResp = await _sendCommand('PWD');
    final originalDir = pwdResp.code == 257
        ? _extractQuoted(pwdResp.message)
        : '/';
    final cwdResp = await _sendCommand('CWD $targetPath');
    if (cwdResp.code == 250) {
      if (originalDir.isNotEmpty) {
        await _sendCommand('CWD $originalDir');
      }
      return SmbStat(
        isFile: false,
        isDirectory: true,
        size: 0,
        modified: DateTime.now().toUtc(),
      );
    }

    throw SmbException('Path "$path" not found', SmbErrorType.fileNotFound);
  }

  String _extractQuoted(String msg) {
    final start = msg.indexOf('"');
    if (start >= 0) {
      final end = msg.indexOf('"', start + 1);
      if (end > start) {
        return msg.substring(start + 1, end);
      }
    }
    return '';
  }

  @override
  Future<void> mkdir(String relative) async {
    final full = _toFtpPath(_resolve(relative));
    final resp = await _sendCommand('MKD $full');
    if (resp.code == 257) return;

    // 550 can mean directory already exists
    if (resp.code == 550) {
      if (await exists(relative)) return;
      throw SmbException(
        'Mkdir failed for "$full": ${resp.message}',
        SmbErrorType.accessDenied,
      );
    }

    throw SmbException(
      'Mkdir failed for "$full": ${resp.message}',
      _mapFtpError(resp.code),
    );
  }

  @override
  Future<bool> exists(String relative) async {
    final full = _toFtpPath(_resolve(relative));
    try {
      // 1. Try SIZE (files)
      final sizeResp = await _sendCommand('SIZE $full');
      if (sizeResp.code == 213) return true;

      // 2. Try MLST
      final mlstResp = await _sendCommand('MLST $full');
      if (mlstResp.code == 250) return true;

      // 3. Try CWD (directories)
      final pwdResp = await _sendCommand('PWD');
      final originalDir = pwdResp.code == 257
          ? _extractQuoted(pwdResp.message)
          : '';
      final cwdResp = await _sendCommand('CWD $full');
      if (cwdResp.code == 250) {
        if (originalDir.isNotEmpty) {
          await _sendCommand('CWD $originalDir');
        }
        return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<void> delete(String relative) async {
    final full = _toFtpPath(_resolve(relative));
    final resp = await _sendCommand('DELE $full');
    if (resp.code == 250) return;

    // Safety rule for 550 on delete: verify whether the file still exists.
    // If it still exists, 550 was permission denied. If gone, it's fileNotFound.
    if (resp.code == 550) {
      if (await exists(relative)) {
        throw SmbException(
          'Delete failed for "$full": Permission denied (${resp.message})',
          SmbErrorType.accessDenied,
        );
      }
      throw SmbException(
        'Delete failed for "$full": File not found',
        SmbErrorType.fileNotFound,
      );
    }

    throw SmbException(
      'Delete failed for "$full": ${resp.message}',
      _mapFtpError(resp.code),
    );
  }

  @override
  Future<void> rename(String from, String to) async {
    final fullFrom = _toFtpPath(_resolve(from));
    final fullTo = _toFtpPath(_resolve(to));

    // Enforce non-overwriting publish: check destination existence first
    if (await exists(to)) {
      throw const SmbException(
        'Destination file already exists',
        SmbErrorType.invalidParam,
      );
    }

    final rnfrResp = await _sendCommand('RNFR $fullFrom');
    if (rnfrResp.code != 350) {
      throw SmbException(
        'Rename failed from "$fullFrom": ${rnfrResp.message}',
        _mapFtpError(rnfrResp.code),
      );
    }

    final rntoResp = await _sendCommand('RNTO $fullTo');
    if (rntoResp.code != 250) {
      throw SmbException(
        'Rename failed to "$fullTo": ${rntoResp.message}',
        _mapFtpError(rntoResp.code),
      );
    }
  }

  @override
  Future<void> upload(
    String relative,
    File file, {
    required void Function() checkpoint,
    required void Function(int) progress,
  }) async {
    final full = _toFtpPath(_resolve(relative));
    final dataSocket = await _openDataSocket();

    try {
      final storResp = await _sendCommand('STOR $full');
      if (storResp.code != 150 && storResp.code != 125) {
        await dataSocket.close();
        throw SmbException(
          'Failed to open FTP upload for "$full": ${storResp.message}',
          _mapFtpError(storResp.code),
        );
      }

      var sent = 0;
      await for (final chunk in file.openRead()) {
        checkpoint();
        dataSocket.add(chunk);
        await dataSocket.flush();
        sent += chunk.length;
        progress(sent);
      }
      checkpoint();
      await dataSocket.close();

      final completeResp = await _readResponse().timeout(_timeout);
      if (completeResp.code != 226 && completeResp.code != 250) {
        throw SmbException(
          'Upload transfer incomplete: ${completeResp.message}',
          SmbErrorType.connection,
        );
      }
    } catch (_) {
      try {
        await dataSocket.close();
      } catch (_) {}
      rethrow;
    }
  }

  @override
  Future<bool> matchesFile(
    File file,
    int length, {
    required void Function() checkpoint,
  }) async {
    checkpoint();
    final fileStat = await stat();
    if (fileStat.size != length) return false;

    var received = 0;
    final remote = await sha256
        .bind(
          read(0, length).map((chunk) {
            checkpoint();
            received += chunk.length;
            return chunk;
          }),
        )
        .first;

    final local = await sha256
        .bind(
          file.openRead().map((chunk) {
            checkpoint();
            return chunk;
          }),
        )
        .first;

    checkpoint();
    return received == length && remote == local;
  }

  @override
  Stream<Uint8List> read(int start, int end) async* {
    final targetPath = _toFtpPath(path);
    final bytesToRead = end - start;
    if (bytesToRead <= 0) return;

    final dataSocket = await _openDataSocket();

    try {
      if (start > 0) {
        final restResp = await _sendCommand('REST $start');
        if (restResp.code != 350) {
          throw SmbException(
            'REST offset $start unsupported: ${restResp.message}',
            SmbErrorType.incompatible,
          );
        }
      }

      final retrResp = await _sendCommand('RETR $targetPath');
      if (retrResp.code != 150 && retrResp.code != 125) {
        await dataSocket.close();
        throw SmbException(
          'Open failed for read "$path": ${retrResp.message}',
          _mapFtpError(retrResp.code),
        );
      }

      var yielded = 0;
      await for (final chunk in dataSocket) {
        if (_closed) break;
        final remaining = bytesToRead - yielded;
        if (remaining <= 0) break;

        if (chunk.length <= remaining) {
          yield chunk;
          yielded += chunk.length;
        } else {
          yield Uint8List.sublistView(chunk, 0, remaining);
          yielded += remaining;
          break;
        }
      }
    } finally {
      try {
        await dataSocket.close();
      } catch (_) {}
      if (!_closed) {
        try {
          await _readResponse().timeout(_timeout);
        } catch (_) {
          await close();
        }
      }
    }
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    try {
      _socket.write('QUIT\r\n');
      await _socket.flush();
    } catch (_) {}
    try {
      await _socketSub.cancel();
    } catch (_) {}
    try {
      await _socket.close();
      _socket.destroy();
    } catch (_) {}
  }

  static SmbErrorType _mapFtpError(int code) => switch (code) {
    530 || 332 => SmbErrorType.auth,
    550 => SmbErrorType.fileNotFound,
    552 || 553 => SmbErrorType.accessDenied,
    421 || 425 || 426 => SmbErrorType.connection,
    500 || 501 || 502 || 504 => SmbErrorType.incompatible,
    _ => SmbErrorType.unknown,
  };
}
