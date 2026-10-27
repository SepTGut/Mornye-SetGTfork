import 'package:flutter/foundation.dart';
import 'package:media_kit/media_kit.dart';
import 'package:mornye/models/equalizer_settings.dart';

/// Shared by every playback deck, including AutoMix's incoming/outgoing decks.
final playbackEqualizer = ValueNotifier<EqualizerSettings>(
  const EqualizerSettings(),
);

/// Windows WASAPI exclusive output preference shared by all media_kit decks.
final windowsExclusiveOutput = ValueNotifier<bool>(false);
final windowsAudioDevice = ValueNotifier<String>('auto');
final windowsAudioDevices = ValueNotifier<List<AudioDevice>>(const [
  AudioDevice('auto', ''),
]);

/// Runtime result for the primary Windows player: active, fallback, or null.
final windowsExclusiveOutputStatus = ValueNotifier<String?>(null);

/// A native error is surfaced in the editor rather than claiming EQ is active.
final playbackEqualizerError = ValueNotifier<String?>(null);

final _errors = <String, String>{};

void reportEqualizerError(String playerId, String? error) {
  if (error == null) {
    _errors.remove(playerId);
  } else {
    _errors[playerId] = error;
  }
  playbackEqualizerError.value = _errors.isEmpty ? null : _errors.values.first;
}
