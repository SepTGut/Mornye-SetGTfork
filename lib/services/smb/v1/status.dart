import 'package:mornye/services/smb/smb_client.dart';

class NtStatus {
  static const int success = 0x00000000;
  static const int noMoreFiles = 0x80000006;
  static const int bufferOverflow = 0x80000005;
  static const int moreProcessingRequired = 0xC0000016;

  static const int logonFailure = 0xC000006D;
  static const int accountRestriction = 0xC000006E;
  static const int invalidLogonHours = 0xC000006F;
  static const int invalidWorkstation = 0xC0000070;
  static const int passwordExpired = 0xC0000071;
  static const int accountDisabled = 0xC0000072;
  static const int wrongPassword = 0xC000006A;
  static const int passwordMustChange = 0xC0000224;

  static const int accessDenied = 0xC0000022;
  static const int objectNameNotFound = 0xC0000034;
  static const int objectPathNotFound = 0xC000003A;
  static const int badNetworkName = 0xC00000CC;
  static const int objectNameCollision = 0xC0000035;
  static const int notADirectory = 0xC0000103;
  static const int fileIsADirectory = 0xC00000BA;
  static const int endOfFile = 0xC0000011;
  static const int invalidParameter = 0xC000000D;
  static const int invalidHandle = 0xC0000008;
  static const int noLogonServers = 0xC000005E;
  static const int notSupported = 0xC00000BB;
  static const int networkNameDeleted = 0xC00000C9;
  static const int connectionDisconnected = 0xC000020C;
  static const int connectionReset = 0xC000020D;

  static SmbErrorType toSmbErrorType(int status) => switch (status) {
    logonFailure ||
    accountRestriction ||
    invalidLogonHours ||
    invalidWorkstation ||
    passwordExpired ||
    accountDisabled ||
    wrongPassword ||
    passwordMustChange => SmbErrorType.auth,

    accessDenied => SmbErrorType.accessDenied,

    objectNameNotFound ||
    objectPathNotFound ||
    badNetworkName => SmbErrorType.fileNotFound,

    notADirectory => SmbErrorType.notADirectory,

    noLogonServers ||
    networkNameDeleted ||
    connectionDisconnected ||
    connectionReset => SmbErrorType.connection,

    invalidParameter ||
    invalidHandle => SmbErrorType.invalidParam,

    _ => SmbErrorType.unknown,
  };

  static String describe(int status) => switch (status) {
    success => 'STATUS_SUCCESS',
    moreProcessingRequired => 'STATUS_MORE_PROCESSING_REQUIRED',
    logonFailure => 'STATUS_LOGON_FAILURE',
    accountRestriction => 'STATUS_ACCOUNT_RESTRICTION',
    passwordExpired => 'STATUS_PASSWORD_EXPIRED',
    accountDisabled => 'STATUS_ACCOUNT_DISABLED',
    wrongPassword => 'STATUS_WRONG_PASSWORD',
    accessDenied => 'STATUS_ACCESS_DENIED',
    objectNameNotFound => 'STATUS_OBJECT_NAME_NOT_FOUND',
    objectPathNotFound => 'STATUS_OBJECT_PATH_NOT_FOUND',
    badNetworkName => 'STATUS_BAD_NETWORK_NAME',
    objectNameCollision => 'STATUS_OBJECT_NAME_COLLISION',
    notADirectory => 'STATUS_NOT_A_DIRECTORY',
    fileIsADirectory => 'STATUS_FILE_IS_A_DIRECTORY',
    endOfFile => 'STATUS_END_OF_FILE',
    invalidParameter => 'STATUS_INVALID_PARAMETER',
    invalidHandle => 'STATUS_INVALID_HANDLE',
    noLogonServers => 'STATUS_NO_LOGON_SERVERS',
    notSupported => 'STATUS_NOT_SUPPORTED',
    _ => 'NTSTATUS 0x${status.toRadixString(16).padLeft(8, '0')}',
  };
}
