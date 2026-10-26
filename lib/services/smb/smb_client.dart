import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

enum SmbErrorType {
  connection,
  timeout,
  auth,
  accessDenied,
  fileNotFound,
  notADirectory,
  invalidParam,
  incompatible,
  unknown,
}

class SmbException implements Exception {
  const SmbException(this.message, [this.type = SmbErrorType.unknown]);
  final String message;
  final SmbErrorType type;

  @override
  String toString() => 'SmbException: $message ($type)';
}

class SmbStat {
  const SmbStat({
    required this.isFile,
    required this.isDirectory,
    required this.size,
    required this.modified,
  });

  final bool isFile;
  final bool isDirectory;
  final int size;
  final DateTime modified;
}

class SmbEntry {
  const SmbEntry({
    required this.name,
    required this.isDirectory,
    required this.size,
    required this.modifiedTime,
  });

  final String name;
  final bool isDirectory;
  final int size;
  final int modifiedTime;
}

class SmbShare {
  const SmbShare({
    required this.name,
    required this.isDisk,
  });

  final String name;
  final bool isDisk;
}

abstract interface class SmbClient {
  String get path;
  Future<List<SmbEntry>> list();
  Future<SmbStat> stat();
  Future<void> mkdir(String relative);
  Future<bool> exists(String relative);
  Future<void> delete(String relative);
  Future<void> rename(String from, String to);
  Future<void> upload(
    String relative,
    File file, {
    required void Function() checkpoint,
    required void Function(int) progress,
  });
  Future<bool> matchesFile(
    File file,
    int length, {
    required void Function() checkpoint,
  });
  Stream<Uint8List> read(int start, int end);
  Future<void> close();
}
