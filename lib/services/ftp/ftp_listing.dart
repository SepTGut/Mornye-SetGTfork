import 'package:mornye/services/smb/smb_client.dart';

class FtpListingItem {
  const FtpListingItem({
    required this.name,
    required this.isDirectory,
    required this.size,
    required this.modifiedTime,
  });

  final String name;
  final bool isDirectory;
  final int size;
  final int modifiedTime;

  SmbEntry toSmbEntry() => SmbEntry(
        name: name,
        isDirectory: isDirectory,
        size: size,
        modifiedTime: modifiedTime,
      );
}

class FtpListingParser {
  static const _safeNameRegex = r'^[^/\\\x00]+$';

  static bool isValidName(String name) {
    if (name.isEmpty || name == '.' || name == '..') return false;
    return RegExp(_safeNameRegex).hasMatch(name);
  }

  /// Parses RFC 3659 MLSD lines:
  /// type=file;size=1234;modify=20261027130000; filename.mp3
  static List<FtpListingItem> parseMlsd(List<String> lines) {
    final results = <FtpListingItem>[];
    for (final rawLine in lines) {
      final line = rawLine.trim();
      if (line.isEmpty) continue;

      final spaceIdx = line.indexOf(' ');
      if (spaceIdx < 0) continue;

      final factsPart = line.substring(0, spaceIdx);
      final name = line.substring(spaceIdx + 1).trim();

      if (!isValidName(name)) continue;

      var isDir = false;
      var size = 0;
      var modifiedTime = 0;

      final facts = factsPart.split(';');
      for (final fact in facts) {
        if (fact.isEmpty) continue;
        final eqIdx = fact.indexOf('=');
        if (eqIdx < 0) continue;
        final key = fact.substring(0, eqIdx).toLowerCase();
        final value = fact.substring(eqIdx + 1);

        switch (key) {
          case 'type':
            final t = value.toLowerCase();
            if (t == 'cdir' || t == 'pdir') {
              // Skip current/parent directory entries
              continue;
            }
            isDir = (t == 'dir');
            break;
          case 'size':
            size = int.tryParse(value) ?? 0;
            break;
          case 'modify':
            modifiedTime = _parseMlsdTimestamp(value);
            break;
        }
      }

      // Check if facts indicated cdir or pdir
      final typeVal = facts
          .firstWhere((f) => f.toLowerCase().startsWith('type='), orElse: () => '')
          .toLowerCase();
      if (typeVal == 'type=cdir' || typeVal == 'type=pdir') {
        continue;
      }

      results.add(
        FtpListingItem(
          name: name,
          isDirectory: isDir,
          size: size,
          modifiedTime: modifiedTime,
        ),
      );
    }
    return results;
  }

  /// Parses RFC 3659 timestamp: YYYYMMDDHHMMSS or YYYYMMDDHHMMSS.sss
  static int _parseMlsdTimestamp(String raw) {
    if (raw.length < 14) return 0;
    try {
      final year = int.parse(raw.substring(0, 4));
      final month = int.parse(raw.substring(4, 6));
      final day = int.parse(raw.substring(6, 8));
      final hour = int.parse(raw.substring(8, 10));
      final minute = int.parse(raw.substring(10, 12));
      final second = int.parse(raw.substring(12, 14));
      final dt = DateTime.utc(year, month, day, hour, minute, second);
      return dt.millisecondsSinceEpoch;
    } catch (_) {
      return 0;
    }
  }

  /// Parses traditional LIST lines (Unix `ls -l` or DOS/Windows style).
  static List<FtpListingItem> parseList(List<String> lines, [DateTime? now]) {
    final referenceDate = now ?? DateTime.now().toUtc();
    final results = <FtpListingItem>[];

    for (final rawLine in lines) {
      final line = rawLine.trim();
      if (line.isEmpty) continue;

      // Try DOS / IIS style first:
      // 10-27-26  01:02PM  <DIR>  FolderName
      // 10-27-26  01:02PM         123456 FileName.mp3
      final dosItem = _parseDosListingLine(line);
      if (dosItem != null) {
        if (isValidName(dosItem.name)) results.add(dosItem);
        continue;
      }

      // Try Unix style:
      // drwxr-xr-x 2 user group 4096 Oct 27 13:00 Music
      // -rw-r--r-- 1 user group 1048576 Oct 27 2025 Song.mp3
      // lrwxrwxrwx 1 user group 11 Oct 27 13:00 Link -> Target
      final unixItem = _parseUnixListingLine(line, referenceDate);
      if (unixItem != null) {
        if (isValidName(unixItem.name)) results.add(unixItem);
        continue;
      }
    }
    return results;
  }

  static FtpListingItem? _parseDosListingLine(String line) {
    // Regex for: MM-DD-YY[YY]  HH:MM[AM|PM]  [<DIR>|size]  name
    final regex = RegExp(
      r'^(\d{2}-\d{2}-\d{2,4})\s+(\d{2}:\d{2}(?:[AP]M)?)\s+(<DIR>|\d+)\s+(.+)$',
      caseSensitive: false,
    );
    final match = regex.firstMatch(line);
    if (match == null) return null;

    final dateStr = match.group(1)!;
    final timeStr = match.group(2)!;
    final dirOrSize = match.group(3)!;
    final name = match.group(4)!.trim();

    final isDir = dirOrSize.toUpperCase() == '<DIR>';
    final size = isDir ? 0 : (int.tryParse(dirOrSize) ?? 0);

    final modifiedTime = _parseDosDateTime(dateStr, timeStr);

    return FtpListingItem(
      name: name,
      isDirectory: isDir,
      size: size,
      modifiedTime: modifiedTime,
    );
  }

  static int _parseDosDateTime(String datePart, String timePart) {
    try {
      final dPieces = datePart.split('-');
      var month = int.parse(dPieces[0]);
      var day = int.parse(dPieces[1]);
      var year = int.parse(dPieces[2]);
      if (year < 100) {
        year += (year < 70 ? 2000 : 1900);
      }

      var hour = 0;
      var minute = 0;
      final upperTime = timePart.toUpperCase();
      final isPm = upperTime.endsWith('PM');
      final isAm = upperTime.endsWith('AM');
      final cleanTime = upperTime.replaceAll(RegExp(r'[AP]M'), '').trim();
      final tPieces = cleanTime.split(':');
      hour = int.parse(tPieces[0]);
      minute = int.parse(tPieces[1]);
      if (isPm && hour < 12) hour += 12;
      if (isAm && hour == 12) hour = 0;

      return DateTime.utc(year, month, day, hour, minute).millisecondsSinceEpoch;
    } catch (_) {
      return 0;
    }
  }

  static FtpListingItem? _parseUnixListingLine(String line, DateTime now) {
    if (line.startsWith('total ')) return null;

    final parts = line.split(RegExp(r'\s+'));
    if (parts.length < 9) return null;

    final permissions = parts[0];
    if (permissions.length < 10) return null;

    final isDir = permissions.startsWith('d');
    final isLink = permissions.startsWith('l');

    final size = int.tryParse(parts[4]) ?? 0;

    // Date is parts[5], parts[6], parts[7]
    // Month: parts[5] (Jan, Feb, ...)
    // Day: parts[6]
    // Year or Time: parts[7] (2025 or 13:00)
    final modifiedTime = _parseUnixDateTime(
      parts[5],
      parts[6],
      parts[7],
      now,
    );

    // Name is remaining parts joined
    var rawName = parts.sublist(8).join(' ');
    if (isLink && rawName.contains(' -> ')) {
      rawName = rawName.split(' -> ').first.trim();
    }

    return FtpListingItem(
      name: rawName,
      isDirectory: isDir,
      size: size,
      modifiedTime: modifiedTime,
    );
  }

  static final _months = {
    'jan': 1,
    'feb': 2,
    'mar': 3,
    'apr': 4,
    'may': 5,
    'jun': 6,
    'jul': 7,
    'aug': 8,
    'sep': 9,
    'oct': 10,
    'nov': 11,
    'dec': 12,
  };

  static int _parseUnixDateTime(
    String monthStr,
    String dayStr,
    String yearOrTime,
    DateTime now,
  ) {
    try {
      final month = _months[monthStr.toLowerCase()] ?? 1;
      final day = int.parse(dayStr);
      var year = now.year;
      var hour = 0;
      var minute = 0;

      if (yearOrTime.contains(':')) {
        final t = yearOrTime.split(':');
        hour = int.parse(t[0]);
        minute = int.parse(t[1]);
        // If date is in the future compared to now, it belongs to last year
        final testDt = DateTime.utc(year, month, day, hour, minute);
        if (testDt.isAfter(now.add(const Duration(days: 1)))) {
          year--;
        }
      } else {
        year = int.parse(yearOrTime);
      }

      return DateTime.utc(year, month, day, hour, minute).millisecondsSinceEpoch;
    } catch (_) {
      return 0;
    }
  }

  /// Parses EPSV reply code 229:
  /// 229 Entering Extended Passive Mode (|||12345|)
  static int parseEpsv(String reply) {
    final regex = RegExp(r'\(\|\|\|(\d+)\|\)');
    final match = regex.firstMatch(reply);
    if (match == null) {
      throw const FormatException('Invalid EPSV reply format');
    }
    final port = int.tryParse(match.group(1)!);
    if (port == null || port < 1 || port > 65535) {
      throw const FormatException('Invalid port in EPSV reply');
    }
    return port;
  }

  /// Parses PASV reply code 227:
  /// 227 Entering Passive Mode (192,168,1,50,195,149)
  /// Returns port only: (p1 * 256) + p2
  static int parsePasv(String reply) {
    final regex = RegExp(r'\((\d+,\d+,\d+,\d+,\d+,\d+)\)');
    final match = regex.firstMatch(reply);
    if (match == null) {
      throw const FormatException('Invalid PASV reply format');
    }
    final parts = match.group(1)!.split(',').map(int.parse).toList();
    if (parts.length != 6) {
      throw const FormatException('Invalid PASV reply numbers');
    }
    final p1 = parts[4];
    final p2 = parts[5];
    final port = (p1 * 256) + p2;
    if (port < 1 || port > 65535) {
      throw const FormatException('Invalid port in PASV reply');
    }
    return port;
  }
}
