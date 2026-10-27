import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:mornye/services/smb/smb_client.dart';
import 'package:mornye/services/smb/v1/md4.dart';

class NtlmResult {
  const NtlmResult({
    required this.authenticateMessage,
    required this.sessionBaseKey,
  });

  final Uint8List authenticateMessage;
  final Uint8List sessionBaseKey;
}

class NtlmContext {
  static const String _signature = 'NTLMSSP\x00';

  static const int flagNegotiateUnicode = 0x00000001;
  static const int flagNegotiateOem = 0x00000002;
  static const int flagRequestTarget = 0x00000004;
  static const int flagNegotiateAnonymous = 0x00000800;
  static const int flagNegotiateNtlm = 0x00000200;
  static const int flagNegotiateAlwaysSign = 0x00008000;
  static const int flagNegotiateExtendedSecurity = 0x00080000;
  static const int flagNegotiateTargetInfo = 0x00800000;
  static const int flagNegotiate128 = 0x20000000;
  static const int flagNegotiate56 = 0x80000000;

  static Uint8List createType1Message({String domain = ''}) {
    final domainBytes = _encodeUtf16Le(domain);
    const flags = flagNegotiateUnicode |
        flagRequestTarget |
        flagNegotiateNtlm |
        flagNegotiateAlwaysSign |
        flagNegotiateExtendedSecurity |
        flagNegotiate128 |
        flagNegotiate56;

    final headerLen = 40;
    final totalLen = headerLen + domainBytes.length;
    final out = Uint8List(totalLen);
    final bd = ByteData.sublistView(out);

    // Signature
    out.setRange(0, 8, _signature.codeUnits);
    // Message Type: 1
    bd.setUint32(8, 1, Endian.little);
    // Flags
    bd.setUint32(12, flags, Endian.little);
    // Domain security buffer
    bd.setUint16(16, domainBytes.length, Endian.little);
    bd.setUint16(18, domainBytes.length, Endian.little);
    bd.setUint32(20, domainBytes.isNotEmpty ? headerLen : 0, Endian.little);
    // Workstation security buffer (empty)
    bd.setUint16(24, 0, Endian.little);
    bd.setUint16(26, 0, Endian.little);
    bd.setUint32(28, 0, Endian.little);
    // OS Version
    bd.setUint8(32, 6); // Major
    bd.setUint8(33, 1); // Minor
    bd.setUint16(34, 7601, Endian.little); // Build
    bd.setUint8(38, 0);
    bd.setUint8(39, 15); // NTLM current revision

    if (domainBytes.isNotEmpty) {
      out.setRange(headerLen, totalLen, domainBytes);
    }
    return out;
  }

  static NtlmResult createType3Message({
    required Uint8List type2Message,
    required String username,
    required String password,
    required String domain,
  }) {
    var msg = type2Message;
    const sig = [0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00];
    for (var i = 0; i <= type2Message.length - 8; i++) {
      var match = true;
      for (var j = 0; j < 8; j++) {
        if (type2Message[i + j] != sig[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        msg = Uint8List.sublistView(type2Message, i);
        break;
      }
    }

    if (msg.length < 32) {
      throw const SmbException(
        'Invalid NTLMSSP Type 2 message',
        SmbErrorType.auth,
      );
    }

    if (username.isEmpty && password.isEmpty) {
      // MS-NLMP Section 3.2.5.1.2: Anonymous NTLMSSP Type 3 message
      const headerLen = 64;
      final out = Uint8List(headerLen);
      final bd = ByteData.sublistView(out);

      // Signature & Message Type
      out.setRange(0, 8, _signature.codeUnits);
      bd.setUint32(8, 3, Endian.little);

      // LM response buffer (empty)
      bd.setUint16(12, 0, Endian.little);
      bd.setUint16(14, 0, Endian.little);
      bd.setUint32(16, headerLen, Endian.little);

      // NT response buffer (empty)
      bd.setUint16(20, 0, Endian.little);
      bd.setUint16(22, 0, Endian.little);
      bd.setUint32(24, headerLen, Endian.little);

      // Domain buffer (empty)
      bd.setUint16(28, 0, Endian.little);
      bd.setUint16(30, 0, Endian.little);
      bd.setUint32(32, headerLen, Endian.little);

      // User buffer (empty)
      bd.setUint16(36, 0, Endian.little);
      bd.setUint16(38, 0, Endian.little);
      bd.setUint32(40, headerLen, Endian.little);

      // Workstation buffer (empty)
      bd.setUint16(44, 0, Endian.little);
      bd.setUint16(46, 0, Endian.little);
      bd.setUint32(48, headerLen, Endian.little);

      // Session key buffer (empty)
      bd.setUint16(52, 0, Endian.little);
      bd.setUint16(54, 0, Endian.little);
      bd.setUint32(56, headerLen, Endian.little);

      // Negotiated Flags with ANONYMOUS bit
      const anonFlags = flagNegotiateUnicode |
          flagNegotiateNtlm |
          flagNegotiateExtendedSecurity |
          flagNegotiateAnonymous;
      bd.setUint32(60, anonFlags, Endian.little);

      return NtlmResult(
        authenticateMessage: out,
        sessionBaseKey: Uint8List(16),
      );
    }

    final bd2 = ByteData.sublistView(msg);
    final serverChallenge = Uint8List.sublistView(msg, 24, 32);

    // Extract target info block if present
    Uint8List targetInfo = Uint8List(0);
    if (msg.length >= 48) {
      final targetInfoLen = bd2.getUint16(40, Endian.little);
      final targetInfoOffset = bd2.getUint32(44, Endian.little);
      if (targetInfoLen > 0 &&
          targetInfoOffset + targetInfoLen <= msg.length) {
        targetInfo = Uint8List.sublistView(
          msg,
          targetInfoOffset,
          targetInfoOffset + targetInfoLen,
        );
      }
    }

    // Generate random 8-byte client challenge
    final random = Random.secure();
    final clientChallenge = Uint8List(8);
    for (var i = 0; i < 8; i++) {
      clientChallenge[i] = random.nextInt(256);
    }

    // Windows FILETIME (100-nanosecond intervals since Jan 1, 1601 UTC)
    final nowMicro = DateTime.now().toUtc().microsecondsSinceEpoch;
    final fileTime = (nowMicro * 10) + 116444736000000000;

    // NTLMv2 hash = HMAC-MD5(key: MD4(UTF-16LE(password)), data: UTF-16LE(UPPER(username) + domain))
    final ntHash = Md4.digest(_encodeUtf16Le(password));
    final userDomainStr = '${username.toUpperCase()}$domain';
    final ntlm2Hash = Uint8List.fromList(
      Hmac(md5, ntHash).convert(_encodeUtf16Le(userDomainStr)).bytes,
    );

    // Temp blob
    final tempBuilder = BytesBuilder(copy: false);
    final tempHeader = Uint8List(28);
    final thBd = ByteData.sublistView(tempHeader);
    thBd.setUint32(0, 0x00000101, Endian.big); // 0x01, 0x01, 0x00, 0x00 signature
    thBd.setUint32(4, 0, Endian.little); // Reserved
    thBd.setUint64(8, fileTime, Endian.little); // Timestamp
    tempHeader.setRange(16, 24, clientChallenge);
    thBd.setUint32(24, 0, Endian.little); // Reserved
    tempBuilder.add(tempHeader);

    if (targetInfo.isNotEmpty) {
      tempBuilder.add(targetInfo);
    } else {
      // Minimal target info with terminating null
      tempBuilder.add(Uint8List(4));
    }
    tempBuilder.add(Uint8List(4)); // 4 zero bytes
    final temp = tempBuilder.takeBytes();

    // nt_proof_str = HMAC-MD5(ntlm2Hash, server_challenge + temp)
    final challengeAndTemp = Uint8List(serverChallenge.length + temp.length);
    challengeAndTemp.setRange(0, serverChallenge.length, serverChallenge);
    challengeAndTemp.setRange(
      serverChallenge.length,
      challengeAndTemp.length,
      temp,
    );
    final ntProofStr = Uint8List.fromList(
      Hmac(md5, ntlm2Hash).convert(challengeAndTemp).bytes,
    );

    // NT response = nt_proof_str + temp
    final ntResponse = Uint8List(ntProofStr.length + temp.length);
    ntResponse.setRange(0, ntProofStr.length, ntProofStr);
    ntResponse.setRange(ntProofStr.length, ntResponse.length, temp);

    // LM response = HMAC-MD5(ntlm2Hash, server_challenge + client_challenge) + client_challenge
    final challengeAndClient = Uint8List(serverChallenge.length + 8);
    challengeAndClient.setRange(0, serverChallenge.length, serverChallenge);
    challengeAndClient.setRange(serverChallenge.length, challengeAndClient.length, clientChallenge);
    final lmProof = Uint8List.fromList(
      Hmac(md5, ntlm2Hash).convert(challengeAndClient).bytes,
    );
    final lmResponse = Uint8List(lmProof.length + 8);
    lmResponse.setRange(0, lmProof.length, lmProof);
    lmResponse.setRange(lmProof.length, lmResponse.length, clientChallenge);

    // Session base key = HMAC-MD5(ntlm2Hash, nt_proof_str)
    final sessionBaseKey = Uint8List.fromList(
      Hmac(md5, ntlm2Hash).convert(ntProofStr).bytes,
    );

    // Construct Type 3 message
    final domainBytes = _encodeUtf16Le(domain);
    final userBytes = _encodeUtf16Le(username);
    final workstationBytes = _encodeUtf16Le('CLIENT');

    const headerLen = 64; // Type 3 header up to flags
    var offset = headerLen;

    final domainOffset = offset;
    offset += domainBytes.length;

    final userOffset = offset;
    offset += userBytes.length;

    final workstationOffset = offset;
    offset += workstationBytes.length;

    final lmOffset = offset;
    offset += lmResponse.length;

    final ntOffset = offset;
    offset += ntResponse.length;

    final totalLen = offset;
    final out = Uint8List(totalLen);
    final bd = ByteData.sublistView(out);

    // Signature & Message Type
    out.setRange(0, 8, _signature.codeUnits);
    bd.setUint32(8, 3, Endian.little);

    // LM response buffer
    bd.setUint16(12, lmResponse.length, Endian.little);
    bd.setUint16(14, lmResponse.length, Endian.little);
    bd.setUint32(16, lmOffset, Endian.little);

    // NT response buffer
    bd.setUint16(20, ntResponse.length, Endian.little);
    bd.setUint16(22, ntResponse.length, Endian.little);
    bd.setUint32(24, ntOffset, Endian.little);

    // Domain buffer
    bd.setUint16(28, domainBytes.length, Endian.little);
    bd.setUint16(30, domainBytes.length, Endian.little);
    bd.setUint32(32, domainOffset, Endian.little);

    // User buffer
    bd.setUint16(36, userBytes.length, Endian.little);
    bd.setUint16(38, userBytes.length, Endian.little);
    bd.setUint32(40, userOffset, Endian.little);

    // Workstation buffer
    bd.setUint16(44, workstationBytes.length, Endian.little);
    bd.setUint16(46, workstationBytes.length, Endian.little);
    bd.setUint32(48, workstationOffset, Endian.little);

    // Session key buffer (empty)
    bd.setUint16(52, 0, Endian.little);
    bd.setUint16(54, 0, Endian.little);
    bd.setUint32(56, 0, Endian.little);

    // Negotiated Flags
    const flags = flagNegotiateUnicode |
        flagNegotiateNtlm |
        flagNegotiateExtendedSecurity |
        flagNegotiateAlwaysSign |
        flagNegotiate128 |
        flagNegotiate56;
    bd.setUint32(60, flags, Endian.little);

    out.setRange(domainOffset, domainOffset + domainBytes.length, domainBytes);
    out.setRange(userOffset, userOffset + userBytes.length, userBytes);
    out.setRange(
      workstationOffset,
      workstationOffset + workstationBytes.length,
      workstationBytes,
    );
    out.setRange(lmOffset, lmOffset + lmResponse.length, lmResponse);
    out.setRange(ntOffset, ntOffset + ntResponse.length, ntResponse);

    return NtlmResult(
      authenticateMessage: out,
      sessionBaseKey: sessionBaseKey,
    );
  }

  static Uint8List _encodeUtf16Le(String text) {
    final units = text.codeUnits;
    final out = Uint8List(units.length * 2);
    final bd = ByteData.sublistView(out);
    for (var i = 0; i < units.length; i++) {
      bd.setUint16(i * 2, units[i], Endian.little);
    }
    return out;
  }
}
