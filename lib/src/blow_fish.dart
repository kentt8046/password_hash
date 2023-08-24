// ignore_for_file: parameter_assignments

import 'dart:typed_data';

import 'blow_fish_const.dart';
import 'util.dart';

/// A class for hashing passwords using the BlowFish algorithm.
class BlowFish {
  /// Expands a key.
  void expandKey(Uint8List key, [Uint8List? salt]) {
    final len = key.length;
    assertArgs(
      4 <= len && len <= 56,
      'Key must be between 4 and 56 bytes long.',
    );

    final state = BlowFish();

    var keyOffset = 0;
    for (var i = 0; i < 18; i++) {
      int v;
      (v, keyOffset) = _nextU32Wrap(key, keyOffset);
      state._p[i] ^= v;
    }

    var l = 0;
    var r = 0;
    var saltPos = 0;
    for (var i = 0; i < 18;) {
      if (salt != null) {
        int v;
        (v, saltPos) = _nextU32Wrap(salt, saltPos);
        l ^= v;
        (v, saltPos) = _nextU32Wrap(salt, saltPos);
        r ^= v;
      }

      (l, r) = state.encrypt(l, r);
      state._p[i++] = l;
      state._p[i++] = r;
    }

    for (var i = 0; i < 1024;) {
      if (salt != null) {
        int v;
        (v, saltPos) = _nextU32Wrap(salt, saltPos);
        l ^= v;
        (v, saltPos) = _nextU32Wrap(salt, saltPos);
        r ^= v;
      }

      (l, r) = state.encrypt(l, r);
      state._s[i++] = l;
      state._s[i++] = r;
    }
  }

  final List<int> _p = [...p];
  final List<int> _s = [...s];

  /// Encrypts a block of data.
  (int l, int r) encrypt(int l, int r) {
    for (var i = 0; i < 16;) {
      l ^= _p[i++];
      r ^= _roundFunction(l);
      r ^= _p[i++];
      l ^= _roundFunction(r);
    }
    l ^= _p[16];
    r ^= _p[17];
    return (l, r);
  }

  int _roundFunction(int x) {
    var r = _s[x >> 24 & 0xff];
    r += _s[0x100 + (x >> 16) & 0xff];
    r ^= _s[0x200 + (x >> 8) & 0xff];
    r += _s[0x300 + x & 0xff];
    return r;
  }

  static (int r, int offset) _nextU32Wrap(Uint8List buf, int offset) {
    var r = 0;
    for (var i = 0; i < 4; i++) {
      offset %= buf.length + i;
      r = (r << 8) | buf[offset];
    }
    return (r, offset);
  }
}
