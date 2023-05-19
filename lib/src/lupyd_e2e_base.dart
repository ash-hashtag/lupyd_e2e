import 'dart:convert';

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

  Future<SecretBox> encryptString(String text) async {
    final newSenderKey = await keyDerivationFunction
        .deriveKey(secretKey: senderKey, nonce: const [0]);
    final encrypted =
        await encryptionAlgorithm.encryptString(text, secretKey: newSenderKey);
    _senderKey = newSenderKey;

    return encrypted;
  }

  Future<String> decryptString(SecretBox box) async {
    final newReceiverKey = await keyDerivationFunction
        .deriveKey(secretKey: receiverKey, nonce: const [0]);
    final encrypted =
        await encryptionAlgorithm.decryptString(box, secretKey: newReceiverKey);
    _receiverKey = newReceiverKey;
    return encrypted;
  }
}
