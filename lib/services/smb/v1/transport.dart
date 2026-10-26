import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:mornye/services/smb/smb_client.dart';

/// Handles raw TCP connection and framing for SMB1 over port 445 (direct-hosted)
/// or port 139 (NetBIOS Session Service).
class Smb1Transport {
  Smb1Transport._(this._socket);

  final Socket _socket;
  final _incomingBuffer = BytesBuilder(copy: false);
  final _pendingReads = <Completer<Uint8List>>[];
  StreamSubscription<Uint8List>? _subscription;
  bool _closed = false;

  static const int defaultPort = 445;
  static const int netBiosPort = 139;
  static const int maxFrameSize = 16 * 1024 * 1024; // 16 MiB guard

  static Future<Smb1Transport> connect(
    String host,
    int port, {
    required Duration timeout,
    String? calledName,
    bool fallbackToNetBios = true,
  }) async {
    try {
      final socket = await Socket.connect(host, port, timeout: timeout);
      socket.setOption(SocketOption.tcpNoDelay, true);

      if (port == netBiosPort) {
        await _negotiateNetBios(socket, calledName ?? '*SMBSERVER', timeout);
      }

      final transport = Smb1Transport._(socket);
      transport._startListening();
      return transport;
    } catch (e) {
      if (fallbackToNetBios && port == defaultPort) {
        try {
          return await connect(
            host,
            netBiosPort,
            timeout: timeout,
            calledName: calledName,
            fallbackToNetBios: false,
          );
        } catch (_) {
          rethrow;
        }
      }
      rethrow;
    }
  }

  static Future<void> _negotiateNetBios(
    Socket socket,
    String calledName,
    Duration timeout,
  ) async {
    final encodedCalled = _encodeNetBiosName(calledName);
    final encodedCalling = _encodeNetBiosName('CLIENT');
    final payload = Uint8List(encodedCalled.length + encodedCalling.length);
    payload.setRange(0, encodedCalled.length, encodedCalled);
    payload.setRange(encodedCalled.length, payload.length, encodedCalling);

    final frame = Uint8List(4 + payload.length);
    frame[0] = 0x81; // Session Request
    frame[1] = 0x00;
    frame[2] = (payload.length >> 8) & 0xFF;
    frame[3] = payload.length & 0xFF;
    frame.setRange(4, frame.length, payload);

    socket.add(frame);
    await socket.flush();

    final respBytes = <int>[];
    final completer = Completer<void>();
    late StreamSubscription<Uint8List> sub;
    sub = socket.listen(
      (chunk) {
        respBytes.addAll(chunk);
        if (respBytes.length >= 4) {
          sub.cancel();
          if (respBytes[0] != 0x82) {
            completer.completeError(
              SmbException(
                'NetBIOS session rejected: code 0x${respBytes[0].toRadixString(16)}',
                SmbErrorType.connection,
              ),
            );
          } else {
            completer.complete();
          }
        }
      },
      onError: completer.completeError,
      cancelOnError: true,
    );

    await completer.future.timeout(
      timeout,
      onTimeout: () {
        sub.cancel();
        throw const SmbException(
          'NetBIOS session request timed out',
          SmbErrorType.timeout,
        );
      },
    );
  }

  void _startListening() {
    _subscription = _socket.listen(
      (chunk) {
        _incomingBuffer.add(chunk);
        _dispatchPending();
      },
      onError: (Object error) {
        _failPending(
          SmbException('Socket error: $error', SmbErrorType.connection),
        );
      },
      onDone: () {
        _closed = true;
        _failPending(
          const SmbException(
            'Connection closed by server',
            SmbErrorType.connection,
          ),
        );
      },
      cancelOnError: true,
    );
  }

  void _dispatchPending() {
    while (_pendingReads.isNotEmpty) {
      final bytes = _incomingBuffer.takeBytes();
      if (bytes.length < 4) {
        _incomingBuffer.add(bytes);
        break;
      }
      final length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
      if (length > maxFrameSize) {
        _failPending(
          SmbException(
            'Frame size exceeds limit: $length bytes',
            SmbErrorType.incompatible,
          ),
        );
        close();
        return;
      }
      if (bytes.length < 4 + length) {
        _incomingBuffer.add(bytes);
        break;
      }

      final packet = Uint8List.sublistView(bytes, 4, 4 + length);
      final remaining = Uint8List.sublistView(bytes, 4 + length);
      if (remaining.isNotEmpty) {
        _incomingBuffer.add(remaining);
      }
      final completer = _pendingReads.removeAt(0);
      completer.complete(packet);
    }
  }

  void _failPending(SmbException error) {
    while (_pendingReads.isNotEmpty) {
      _pendingReads.removeAt(0).completeError(error);
    }
  }

  Future<void> sendPacket(Uint8List payload) async {
    if (_closed) {
      throw const SmbException(
        'Cannot send on closed connection',
        SmbErrorType.connection,
      );
    }
    final length = payload.length;
    final header = Uint8List(4);
    header[0] = 0x00;
    header[1] = (length >> 16) & 0xFF;
    header[2] = (length >> 8) & 0xFF;
    header[3] = length & 0xFF;

    _socket.add(header);
    _socket.add(payload);
    await _socket.flush();
  }

  Future<Uint8List> receivePacket(Duration timeout) {
    if (_closed) {
      throw const SmbException('Connection closed', SmbErrorType.connection);
    }
    final completer = Completer<Uint8List>();
    _pendingReads.add(completer);
    _dispatchPending();

    return completer.future.timeout(
      timeout,
      onTimeout: () {
        _pendingReads.remove(completer);
        throw const SmbException(
          'SMB read timed out',
          SmbErrorType.timeout,
        );
      },
    );
  }


  static Uint8List _encodeNetBiosName(String name) {
    final upper = name.toUpperCase().padRight(16, ' ').substring(0, 16);
    final encoded = Uint8List(32);
    for (var i = 0; i < 16; i++) {
      final code = upper.codeUnitAt(i);
      encoded[2 * i] = ((code >> 4) & 0x0F) + 0x41;
      encoded[2 * i + 1] = (code & 0x0F) + 0x41;
    }
    return encoded;
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    try {
      await _subscription?.cancel();
      _socket.destroy();
    } catch (_) {}
  }
}
