import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:mornye/services/smb/smb_client.dart';
import 'package:mornye/services/smb/v1/commands.dart';
import 'package:mornye/services/smb/v1/ntlm.dart';
import 'package:mornye/services/smb/v1/packet.dart';
import 'package:mornye/services/smb/v1/shares.dart';
import 'package:mornye/services/smb/v1/signing.dart';
import 'package:mornye/services/smb/v1/status.dart';
import 'package:mornye/services/smb/v1/transport.dart';
import 'package:synchronized/synchronized.dart';

/// Pure Dart implementation of SMBv1 (NT LM 0.12).
class Smb1Client implements SmbClient {
  Smb1Client._(
    this._transport,
    this.path, {
    required int uid,
    required int tid,
    Smb1Signer? signer,
    required Duration timeout,
  })  : _uid = uid,
        _tid = tid,
        _signer = signer,
        _timeout = timeout;

  final Smb1Transport _transport;
  @override
  final String path;
  int _uid;
  int _tid;
  final Smb1Signer? _signer;
  final Duration _timeout;
  int _mid = 0;
  final _lock = Lock();
  bool _closed = false;

  static Future<Smb1Client> connect(
    Uri target, {
    required String username,
    required String password,
    required String domain,
    required Duration timeout,
  }) async {
    final host = target.host;
    final port = target.hasPort ? target.port : Smb1Transport.defaultPort;
    final segments = target.pathSegments.where((s) => s.isNotEmpty).toList();
    final shareName = segments.isEmpty ? 'IPC\$' : segments.first;

    final transport = await Smb1Transport.connect(host, port, timeout: timeout);
    var mid = 0;

    Future<Smb1Packet> roundTrip(
      Smb1Packet request, {
      Smb1Signer? signer,
    }) async {
      mid = (mid + 1) & 0xFFFF;
      request.mid = mid;
      final encoded = request.encode();
      signer?.sign(encoded);
      await transport.sendPacket(encoded);
      final respBytes = await transport.receivePacket(timeout);
      signer?.verify(respBytes);
      return Smb1Packet.decode(respBytes);
    }

    try {
      // 1. Negotiate
      final negReq = Smb1Commands.createNegotiateRequest();
      final negResp = await roundTrip(negReq);
      final negResult = Smb1Commands.parseNegotiateResponse(negResp);

      // 2. Session Setup (NTLMSSP)
      Smb1Signer? signer;
      int uid = 0;

      if (negResult.extendedSecurity) {
        // Type 1 Negotiate
        final type1 = NtlmContext.createType1Message(domain: domain);
        final setup1Req = Smb1Commands.createSessionSetupRequest(
          securityBlob: type1,
          maxBufferSize: negResult.maxBufferSize,
        );
        final setup1Resp = await roundTrip(setup1Req);
        uid = setup1Resp.uid;

        if (setup1Resp.status != NtStatus.moreProcessingRequired &&
            setup1Resp.status != NtStatus.success) {
          throw SmbException(
            'Session setup failed: ${NtStatus.describe(setup1Resp.status)}',
            NtStatus.toSmbErrorType(setup1Resp.status),
          );
        }

        // Type 2 Challenge from server
        final type2Blob = setup1Resp.bytes;
        final ntlmResult = NtlmContext.createType3Message(
          type2Message: type2Blob,
          username: username,
          password: password,
          domain: domain,
        );

        // Type 3 Authenticate
        final setup2Req = Smb1Commands.createSessionSetupRequest(
          securityBlob: ntlmResult.authenticateMessage,
          uid: uid,
          maxBufferSize: negResult.maxBufferSize,
        );
        final setup2Resp = await roundTrip(setup2Req);
        uid = setup2Resp.uid;

        if (setup2Resp.status != NtStatus.success) {
          throw SmbException(
            'Authentication failed: ${NtStatus.describe(setup2Resp.status)}',
            NtStatus.toSmbErrorType(setup2Resp.status),
          );
        }

        if (negResult.signingRequired || negResult.signingEnabled) {
          signer = Smb1Signer(
            macKey: ntlmResult.sessionBaseKey,
            required: negResult.signingRequired,
          );
        }
      } else {
        throw const SmbException(
          'Server does not support extended security (NTLMSSP)',
          SmbErrorType.incompatible,
        );
      }

      // 3. Tree Connect
      final treePath = '\\\\$host\\$shareName';
      final treeReq = Smb1Commands.createTreeConnectRequest(
        path: treePath,
        uid: uid,
      );
      final treeResp = await roundTrip(treeReq, signer: signer);
      if (treeResp.status != NtStatus.success) {
        throw SmbException(
          'Failed to connect to share "$shareName": ${NtStatus.describe(treeResp.status)}',
          NtStatus.toSmbErrorType(treeResp.status),
        );
      }
      final tid = treeResp.tid;
      final relativePath = segments.skip(1).join('/');

      return Smb1Client._(
        transport,
        relativePath,
        uid: uid,
        tid: tid,
        signer: signer,
        timeout: timeout,
      );
    } catch (_) {
      await transport.close();
      rethrow;
    }
  }

  static Future<List<SmbShare>> shares(
    Uri target, {
    required String username,
    required String password,
    required String domain,
    required Duration timeout,
  }) async {
    final client = await connect(
      Uri(
        scheme: target.scheme,
        host: target.host,
        port: target.hasPort ? target.port : null,
        path: '/IPC\$',
      ),
      username: username,
      password: password,
      domain: domain,
      timeout: timeout,
    );
    try {
      final req = Smb1Shares.createNetShareEnumRequest(
        tid: client._tid,
        uid: client._uid,
      );
      final resp = await client._roundTrip(req);
      return Smb1Shares.parseNetShareEnumResponse(resp);
    } finally {
      await client.close();
    }
  }

  Future<Smb1Packet> _roundTrip(Smb1Packet request) =>
      _lock.synchronized(() async {
        if (_closed) {
          throw const SmbException(
            'Client is closed',
            SmbErrorType.connection,
          );
        }
        _mid = (_mid + 1) & 0xFFFF;
        request.mid = _mid;
        request.uid = _uid;
        request.tid = _tid;

        final encoded = request.encode();
        _signer?.sign(encoded);
        await _transport.sendPacket(encoded);

        final respBytes = await _transport.receivePacket(_timeout);
        _signer?.verify(respBytes);
        return Smb1Packet.decode(respBytes);
      });

  @override
  Future<List<SmbEntry>> list() async {
    final searchPath = path.isEmpty ? '' : path;
    var req = Smb1Commands.createFindFirst2Request(
      directoryPath: searchPath,
      tid: _tid,
      uid: _uid,
    );
    var resp = await _roundTrip(req);

    final entries = <SmbEntry>[];
    var result = Smb1Commands.parseFindBothDirectoryInfo(resp);
    for (final e in result.entries) {
      if (e.name != '.' && e.name != '..') {
        entries.add(
          SmbEntry(
            name: e.name,
            isDirectory: e.isDirectory,
            size: e.size,
            modifiedTime: e.modifiedTime,
          ),
        );
      }
    }

    var sid = result.sid;
    var endOfSearch = result.endOfSearch;

    while (!endOfSearch && entries.isNotEmpty) {
      final last = entries.last;
      req = Smb1Commands.createFindNext2Request(
        sid: sid,
        resumeKey: 0,
        lastName: last.name,
        tid: _tid,
        uid: _uid,
      );
      resp = await _roundTrip(req);
      result = Smb1Commands.parseFindBothDirectoryInfo(resp);
      for (final e in result.entries) {
        if (e.name != '.' && e.name != '..') {
          entries.add(
            SmbEntry(
              name: e.name,
              isDirectory: e.isDirectory,
              size: e.size,
              modifiedTime: e.modifiedTime,
            ),
          );
        }
      }
      endOfSearch = result.endOfSearch || result.entries.isEmpty;
    }
    return entries;
  }

  @override
  Future<SmbStat> stat() async {
    final req = Smb1Commands.createNtCreateRequest(
      path: path,
      tid: _tid,
      uid: _uid,
      write: false,
    );
    final resp = await _roundTrip(req);
    if (resp.status != NtStatus.success) {
      throw SmbException(
        'Stat failed for "$path": ${NtStatus.describe(resp.status)}',
        NtStatus.toSmbErrorType(resp.status),
      );
    }
    final fid = resp.words[2];
    final lastWriteTime = (resp.words.length >= 16)
        ? (resp.words[12] |
            (resp.words[13] << 16) |
            (resp.words[14] << 32) |
            (resp.words[15] << 48))
        : 0;
    final fileAttrs = (resp.words.length >= 19) ? resp.words[18] : 0;
    final isDir = (fileAttrs & 0x10) != 0;
    final endOfFile = (resp.words.length >= 27)
        ? (resp.words[23] |
            (resp.words[24] << 16) |
            (resp.words[25] << 32) |
            (resp.words[26] << 48))
        : 0;

    await _closeHandle(fid);

    final modifiedMs = (lastWriteTime > 116444736000000000)
        ? ((lastWriteTime - 116444736000000000) ~/ 10000)
        : DateTime.now().millisecondsSinceEpoch;

    return SmbStat(
      isFile: !isDir,
      isDirectory: isDir,
      size: endOfFile,
      modified: DateTime.fromMillisecondsSinceEpoch(modifiedMs, isUtc: true),
    );
  }

  @override
  Future<void> mkdir(String relative) async {
    final full = _join(path, relative);
    final req = Smb1Commands.createCreateDirectoryRequest(
      path: full,
      tid: _tid,
      uid: _uid,
    );
    final resp = await _roundTrip(req);
    if (resp.status != NtStatus.success &&
        resp.status != NtStatus.objectNameCollision) {
      throw SmbException(
        'Mkdir failed for "$full": ${NtStatus.describe(resp.status)}',
        NtStatus.toSmbErrorType(resp.status),
      );
    }
  }

  @override
  Future<bool> exists(String relative) async {
    final full = _join(path, relative);
    try {
      final req = Smb1Commands.createNtCreateRequest(
        path: full,
        tid: _tid,
        uid: _uid,
        write: false,
      );
      final resp = await _roundTrip(req);
      if (resp.status == NtStatus.success) {
        await _closeHandle(resp.words[2]);
        return true;
      }
      if (resp.status == NtStatus.objectNameNotFound ||
          resp.status == NtStatus.objectPathNotFound) {
        return false;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<void> delete(String relative) async {
    final full = _join(path, relative);
    final req = Smb1Commands.createDeleteRequest(
      path: full,
      tid: _tid,
      uid: _uid,
    );
    final resp = await _roundTrip(req);
    if (resp.status != NtStatus.success) {
      throw SmbException(
        'Delete failed for "$full": ${NtStatus.describe(resp.status)}',
        NtStatus.toSmbErrorType(resp.status),
      );
    }
  }

  @override
  Future<void> rename(String from, String to) async {
    final fullFrom = _join(path, from);
    final fullTo = _join(path, to);

    // Enforce non-overwriting publish (replace_if_exist = 0)
    if (await exists(to)) {
      throw const SmbException(
        'Destination file already exists',
        SmbErrorType.invalidParam,
      );
    }

    final req = Smb1Commands.createRenameRequest(
      from: fullFrom,
      to: fullTo,
      tid: _tid,
      uid: _uid,
    );
    final resp = await _roundTrip(req);
    if (resp.status != NtStatus.success) {
      throw SmbException(
        'Rename failed from "$fullFrom" to "$fullTo": ${NtStatus.describe(resp.status)}',
        NtStatus.toSmbErrorType(resp.status),
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
    final full = _join(path, relative);
    final createReq = Smb1Commands.createNtCreateRequest(
      path: full,
      tid: _tid,
      uid: _uid,
      write: true,
      disposition: 5, // FILE_OVERWRITE_IF
    );
    final createResp = await _roundTrip(createReq);
    if (createResp.status != NtStatus.success) {
      throw SmbException(
        'Failed to open file for write: "$full": ${NtStatus.describe(createResp.status)}',
        NtStatus.toSmbErrorType(createResp.status),
      );
    }
    final fid = createResp.words[2];

    try {
      var offset = 0;
      await for (final chunk in file.openRead()) {
        checkpoint();
        final bytes = Uint8List.fromList(chunk);
        var chunkOffset = 0;
        const maxWrite = 60 * 1024;

        while (chunkOffset < bytes.length) {
          final writeLen = min(maxWrite, bytes.length - chunkOffset);
          final slice = Uint8List.sublistView(
            bytes,
            chunkOffset,
            chunkOffset + writeLen,
          );
          final writeReq = Smb1Commands.createWriteRequest(
            fid: fid,
            offset: offset + chunkOffset,
            data: slice,
            tid: _tid,
            uid: _uid,
          );
          final writeResp = await _roundTrip(writeReq);
          if (writeResp.status != NtStatus.success) {
            throw SmbException(
              'Write failed: ${NtStatus.describe(writeResp.status)}',
              NtStatus.toSmbErrorType(writeResp.status),
            );
          }
          chunkOffset += writeLen;
        }
        offset += bytes.length;
        progress(offset);
      }
      checkpoint();
      final flushReq = Smb1Commands.createFlushRequest(
        fid: fid,
        tid: _tid,
        uid: _uid,
      );
      await _roundTrip(flushReq);
    } finally {
      await _closeHandle(fid);
    }
  }

  @override
  Future<bool> matchesFile(
    File file,
    int length, {
    required void Function() checkpoint,
  }) async {
    checkpoint();
    final req = Smb1Commands.createNtCreateRequest(
      path: path,
      tid: _tid,
      uid: _uid,
      write: false,
    );
    final resp = await _roundTrip(req);
    if (resp.status != NtStatus.success) return false;
    final fid = resp.words[2];
    final endOfFile = (resp.words.length >= 27)
        ? (resp.words[23] |
            (resp.words[24] << 16) |
            (resp.words[25] << 32) |
            (resp.words[26] << 48))
        : 0;

    try {
      if (endOfFile != length) return false;
      var received = 0;
      final remote = await sha256
          .bind(
            _readHandle(fid, 0, length).map((chunk) {
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
    } finally {
      await _closeHandle(fid);
    }
  }

  @override
  Stream<Uint8List> read(int start, int end) async* {
    final req = Smb1Commands.createNtCreateRequest(
      path: path,
      tid: _tid,
      uid: _uid,
      write: false,
    );
    final resp = await _roundTrip(req);
    if (resp.status != NtStatus.success) {
      throw SmbException(
        'Open failed for read: "$path": ${NtStatus.describe(resp.status)}',
        NtStatus.toSmbErrorType(resp.status),
      );
    }
    final fid = resp.words[2];
    try {
      yield* _readHandle(fid, start, end);
    } finally {
      await _closeHandle(fid);
    }
  }

  Stream<Uint8List> _readHandle(int fid, int start, int end) async* {
    var offset = start;
    const maxRead = 60 * 1024;
    while (offset < end && !_closed) {
      final toRead = min(maxRead, end - offset);
      final req = Smb1Commands.createReadRequest(
        fid: fid,
        offset: offset,
        length: toRead,
        tid: _tid,
        uid: _uid,
      );
      final resp = await _roundTrip(req);
      if (resp.status != NtStatus.success && resp.status != NtStatus.endOfFile) {
        throw SmbException(
          'Read failed at offset $offset: ${NtStatus.describe(resp.status)}',
          NtStatus.toSmbErrorType(resp.status),
        );
      }
      final dataLen = (resp.words.length >= 6) ? resp.words[5] : 0;
      final data = (resp.bytes.length >= dataLen)
          ? Uint8List.sublistView(resp.bytes, resp.bytes.length - dataLen)
          : resp.bytes;

      if (data.isEmpty) {
        throw StateError('SMB file ended before requested range');
      }
      offset += data.length;
      yield data;
    }
  }

  Future<void> _closeHandle(int fid) async {
    try {
      final req = Smb1Commands.createCloseRequest(
        fid: fid,
        tid: _tid,
        uid: _uid,
      );
      await _roundTrip(req);
    } catch (_) {}
  }

  String _join(String parent, String child) {
    if (parent.isEmpty) return child;
    if (child.isEmpty) return parent;
    final p = parent.endsWith('/') ? parent.substring(0, parent.length - 1) : parent;
    final c = child.startsWith('/') ? child.substring(1) : child;
    return '$p/$c';
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    try {
      final req = Smb1Commands.createTreeDisconnectRequest(tid: _tid);
      await _roundTrip(req);
    } catch (_) {}
    try {
      final req = Smb1Commands.createLogoffRequest(uid: _uid);
      await _roundTrip(req);
    } catch (_) {}
    await _transport.close();
  }
}
