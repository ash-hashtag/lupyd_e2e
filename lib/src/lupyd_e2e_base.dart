import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

SecretBox secretBoxFromMap(Map map) {
  return SecretBox(List.from(map['M']!),
      nonce: List.from(map['n']!), mac: Mac(List.from(map['m']!)));
}

SecretBox secretBoxfromJson(String jsonData) {
  return secretBoxFromMap(Map.from(json.decode(jsonData)));
}

extension ToMap on SecretBox {
  Map<String, List<int>> toMap() {
    return {
      "M": cipherText,
      "n": nonce,
      "m": mac.bytes,
    };
  }
}

class EncryptedMessage {
  final List<int> message, nonce, mac;

  EncryptedMessage({
    required this.message,
    required this.nonce,
    required this.mac,
  });

  factory EncryptedMessage.fromSecretBox(SecretBox box) {
    return EncryptedMessage(
      message: box.cipherText,
      nonce: box.nonce,
      mac: box.mac.bytes,
    );
  }

  SecretBox toSecretBox() {
    return SecretBox(message, nonce: nonce, mac: Mac(mac));
  }

  Map<String, List<int>> toMap() {
    return {
      "n": nonce,
      "m": mac,
      "M": message,
    };
  }
}

class KeyPairBytes {
  List<int> publicKey, privateKey;

  KeyPairBytes({required this.publicKey, required this.privateKey});

  SimpleKeyPair toKeyPair({KeyPairType type = KeyPairType.x25519}) {
    final simplePublicKey = SimplePublicKey(publicKey, type: type);
    final simpleKeyPair =
        SimpleKeyPairData(privateKey, type: type, publicKey: simplePublicKey);
    return simpleKeyPair;
  }
}

class DoubleRatchet {
  SecretKey _senderKey, _receiverKey;
  static final keyPairAlgorithm = X25519();
  static final encryptionAlgorithm =
      AesCbc.with256bits(macAlgorithm: Hmac.sha256());
  static final keyDerivationFunction =
      Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  DoubleRatchet({
    required SecretKey senderKey,
    required SecretKey receiverKey,
  })  : _senderKey = senderKey,
        _receiverKey = receiverKey;

  factory DoubleRatchet.fromByteKeys(
      List<int> senderKey, List<int> receiverKey) {
    return DoubleRatchet(
        senderKey: SecretKey(senderKey), receiverKey: SecretKey(receiverKey));
  }

  factory DoubleRatchet.fromMap(Map<String, List> map) {
    return DoubleRatchet.fromByteKeys(
        List.from(map['sender']!), List.from(map['receiver']!));
  }

  Future<Map<String, List<int>>> toMap() async {
    final senderKeyBytes = senderKey.extractBytes();
    final receiverKeyBytes = receiverKey.extractBytes();
    return {
      "sender": await senderKeyBytes,
      "receiver": await receiverKeyBytes,
    };
  }

  SecretKey get senderKey => _senderKey;
  SecretKey get receiverKey => _receiverKey;

  Future<EncryptedMessage> encryptString(String text) async {
    final newSenderKey = await keyDerivationFunction
        .deriveKey(secretKey: senderKey, nonce: const [0]);
    final encrypted =
        await encryptionAlgorithm.encryptString(text, secretKey: newSenderKey);
    _senderKey = newSenderKey;

    return EncryptedMessage.fromSecretBox(encrypted);
  }

  Future<String> decryptString(EncryptedMessage encryptedMessage) async {
    final newReceiverKey = await keyDerivationFunction
        .deriveKey(secretKey: receiverKey, nonce: const [0]);
    final box = encryptedMessage.toSecretBox();
    final encrypted =
        await encryptionAlgorithm.decryptString(box, secretKey: newReceiverKey);
    _receiverKey = newReceiverKey;
    return encrypted;
  }
}

extension Bytes on Random {
  Uint8List nextBytes(int length) {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = nextInt(256);
    }
    return bytes;
  }
}

class EncryptedStream {
  final Stream<List<int>> stream;
  final List<int> nonce, secretKey;
  final FutureOr<Mac> mac;

  EncryptedStream({
    required this.stream,
    required this.nonce,
    required this.mac,
    required this.secretKey,
  });
  Future<Map<String, List<int>>> encryptionDetailsToMap() async {
    return {"m": (await mac).bytes, "n": nonce, "k": secretKey};
  }
}

EncryptedStream encryptStream(Stream<List<int>> inputStream) {
  final rng = Random.secure();

  final keyBytes = rng.nextBytes(32);
  final key = SecretKey(keyBytes);

  final algorithm = AesCbc.with256bits(macAlgorithm: Hmac.sha256());

  final nonce = rng.nextBytes(16);
  final macCompleter = Completer<Mac>();
  void onMac(Mac mac) {
    macCompleter.complete(mac);
  }

  final stream = algorithm.encryptStream(inputStream,
      secretKey: key, onMac: onMac, nonce: nonce);
  final encryptedStream = EncryptedStream(
      stream: stream,
      nonce: nonce,
      secretKey: keyBytes,
      mac: macCompleter.future);

  return encryptedStream;
}

Stream<List<int>> decryptStream(EncryptedStream encryptedStream) {
  final algorithm = AesCbc.with256bits(macAlgorithm: Hmac.sha256());
  return algorithm.decryptStream(encryptedStream.stream,
      secretKey: SecretKey(encryptedStream.secretKey),
      nonce: encryptedStream.nonce,
      mac: encryptedStream.mac);
}

class EncryptedFile {
  File file;
  List<int> secretKey, nonce, mac;

  EncryptedFile({
    required this.file,
    required this.nonce,
    required this.mac,
    required this.secretKey,
  });
  Map<String, List<int>> encryptionDetailsToMap() {
    return {"m": mac, "n": nonce, "k": secretKey};
  }
}

Future<EncryptedFile> encryptFile(File input, File output) async {
  final encryptedStream = encryptStream(input.openRead());

  await output.create(recursive: true);

  final sink = output.openWrite();
  await sink.addStream(encryptedStream.stream);
  await sink.flush();
  await sink.close();

  return EncryptedFile(
      file: output,
      nonce: encryptedStream.nonce,
      mac: (await encryptedStream.mac).bytes,
      secretKey: encryptedStream.secretKey);
}

class EncryptedBytes {
  List<int> bytes;
  List<int> nonce, mac, secretKey;

  EncryptedBytes({
    required this.bytes,
    required this.nonce,
    required this.mac,
    required this.secretKey,
  });

  Map<String, List<int>> encryptionDetailsToMap() {
    return {"m": mac, "n": nonce, "k": secretKey};
  }
}

Future encryptBytes(Uint8List bytes) async {
  final algorithm = AesCbc.with256bits(macAlgorithm: Hmac.sha256());
  final rng = Random.secure();

  final keyBytes = rng.nextBytes(32);
  final nonce = rng.nextBytes(16);

  final box = await algorithm.encrypt(bytes,
      secretKey: SecretKey(keyBytes), nonce: nonce);

  return EncryptedBytes(
    bytes: box.cipherText,
    nonce: box.nonce,
    mac: box.mac.bytes,
    secretKey: keyBytes,
  );
}
