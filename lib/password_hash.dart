import 'dart:convert';
import 'dart:typed_data';

import 'src/bcrypt.dart';
import 'src/stretching_cost.dart';
import 'src/util.dart';

export 'src/stretching_cost.dart';

const _bcrypt = BCrypt();

/// Generates a password hash using the BCrypt algorithm.
String generatePasswordHash(
  String password, {
  int cost = StretchingCost.defaultCost,
}) {
  final salt = BCrypt.generateSalt();
  final hash = _genHash(password, salt, cost);
  return '\$2b\$$cost\$${bytesToBase64(salt)}${bytesToBase64(hash)}';
}

/// Checks if a password matches a hash.
bool verifyPassword(String password, String passwordHash) {
  final parts = passwordHash.split(r'$');
  if (parts.length != 4 || parts[1] != '2b') return false;

  final cost = int.tryParse(parts[2]);
  if (cost == null || parts[3].length != 53) return false;

  final salt = base64ToBytes(parts[3].substring(0, 22));
  final hash = parts[3].substring(22);

  final newHash = _genHash(password, salt, cost);

  return bytesToBase64(newHash) == hash;
}

Uint8List _genHash(String password, Uint8List salt, int cost) {
  final bytes = Uint8List.fromList(utf8.encode(password));
  return _bcrypt.createHash(bytes, salt, cost: cost).sublist(0, 23);
}
