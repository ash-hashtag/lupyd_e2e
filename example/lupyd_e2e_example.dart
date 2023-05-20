import 'dart:convert';
import 'dart:io';

import 'package:lupyd_e2e/lupyd_e2e.dart';

void main() async {
  await fileEncryptionTest();
}

Future<void> fileEncryptionTest() async {
  final file = File("testfile");
  final encrypted = encryptStream(file.openRead());

  final decrypted = decryptStream(encrypted);

  final text = utf8.decode(await decrypted.expand((e) => e).toList());

  print("Mac: ${await encrypted.mac}");
  print(text);
}
