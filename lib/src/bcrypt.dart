import 'dart:math';
import 'dart:typed_data';

import 'blow_fish.dart';
import 'stretching_cost.dart';
import 'util.dart';

/// A class for hashing passwords using the BCrypt algorithm.
class BCrypt {
  /// Creates a new BCrypt instance.
  const BCrypt();

  static final _rand = Random.secure();

  /// Hashes a password using the BCrypt algorithm.
  ///
  /// * `password`: The password to hash.
  /// * `salt`: The salt to use when hashing the password.
  /// * `cost`: The logarithmic cost of hashing the password. The cost must be
  ///   between [StretchingCost.minCost] and [StretchingCost.maxCost], inclusive.
  ///
  /// Returns the hashed password.
  ///
  /// Throws an [ArgumentError] if `cost` is not between [StretchingCost.minCost] and
  /// [StretchingCost.maxCost], inclusive.
  Uint8List createHash(
    Uint8List password,
    Uint8List salt, {
    int cost = StretchingCost.defaultCost,
  }) {
    assertArgs(
      StretchingCost.minCost <= cost && cost <= StretchingCost.maxCost,
      'Cost must be between ${StretchingCost.minCost} and ${StretchingCost.maxCost}, inclusive.',
    );
    assertArgs(salt.length == 16, 'Salt must be 16 bytes long.');
    assertArgs(password.isNotEmpty, 'Password must be at least one byte long.');

    // ignore: parameter_assignments
    if (password.length > 72) password = password.sublist(0, 72);

    final state = _setup(cost, salt, password);

    // OrpheanBeholderScryDoubt
    final ctext = [
      0x4f727068,
      0x65616e42,
      0x65686f6c,
      0x64657253,
      0x63727944,
      0x6f756274,
    ];

    final hash = List.filled(24, 0);

    for (var i = 0; i < ctext.length; i += 2) {
      var l = ctext[i];
      var r = ctext[i + 1];

      for (var j = 0; j < 64; j++) {
        (l, r) = state.encrypt(l, r);
      }

      hash[i * 4 + 0] = l >> 24 & 0xff;
      hash[i * 4 + 1] = l >> 16 & 0xff;
      hash[i * 4 + 2] = l >> 8 & 0xff;
      hash[i * 4 + 3] = l & 0xff;
      hash[i * 4 + 4] = r >> 24 & 0xff;
      hash[i * 4 + 5] = r >> 16 & 0xff;
      hash[i * 4 + 6] = r >> 8 & 0xff;
      hash[i * 4 + 7] = r & 0xff;
    }

    return Uint8List.fromList(hash);
  }

  BlowFish _setup(int cost, Uint8List salt, Uint8List password) {
    final state = BlowFish()..expandKey(password, salt);

    for (var i = 0, end = 1 << cost; i < end; i++) {
      state
        ..expandKey(password)
        ..expandKey(salt);
    }

    return state;
  }

  /// Create a salt for use with [createHash].
  static Uint8List generateSalt() =>
      Uint8List.fromList(List.generate(16, (_) => _rand.nextInt(256)));
}
