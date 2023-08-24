import 'package:password_hash/password_hash.dart';

void main(List<String> arguments) {
  final hash = generatePasswordHash('password');
  print(hash);
  print(verifyPassword('password', hash));
}
