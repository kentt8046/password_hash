// ignore_for_file: avoid_positional_boolean_parameters

import 'dart:convert';
import 'dart:typed_data';

/// Asserts that the given [condition] is `true`.
void assertArgs(bool condition, String message) {
  if (!condition) throw ArgumentError(message);
}

/// Converts a list of bytes to a base64 string.
String bytesToBase64(List<int> bytes) {
  return base64Encode(bytes).replaceAll('=', '');
}

/// Converts a base64 string to a list of bytes.
Uint8List base64ToBytes(String base64) {
  return base64Decode('$base64==');
}
