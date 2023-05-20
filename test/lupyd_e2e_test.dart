import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:lupyd_e2e/lupyd_e2e.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('E2E Test', e2eTest);
    test('default test', defaultTest);
  });
}

bool areListsEqual<T>(List<T> a, List<T> b) {
  if (a == b) return true;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }

  return true;
}

void defaultTest() async {
  const type = KeyPairType.x25519;
  var aliceKeyPair = await DoubleRatchet.keyPairAlgorithm.newKeyPair();
  var alicePublicKey = await aliceKeyPair.extractPublicKey();
  alicePublicKey = SimplePublicKey(alicePublicKey.bytes, type: type);
  aliceKeyPair = SimpleKeyPairData(await aliceKeyPair.extractPrivateKeyBytes(),
      type: type, publicKey: alicePublicKey);

  var bobKeyPair = await DoubleRatchet.keyPairAlgorithm.newKeyPair();
  var bobPublicKey = await bobKeyPair.extractPublicKey();
  bobPublicKey = SimplePublicKey(bobPublicKey.bytes, type: type);
  bobKeyPair = SimpleKeyPairData(await bobKeyPair.extractPrivateKeyBytes(),
      type: type, publicKey: bobPublicKey);

  final sharedSecretKeyAlice = await X25519().sharedSecretKey(
      keyPair: aliceKeyPair,
      remotePublicKey: await bobKeyPair.extractPublicKey());

  final sharedSecretKeyBob = await X25519()
      .sharedSecretKey(keyPair: bobKeyPair, remotePublicKey: alicePublicKey);
  print(
      "shared secret key equal ${areListsEqual(await sharedSecretKeyAlice.extractBytes(), await sharedSecretKeyBob.extractBytes())}");
  final message = crap();
  var cipher = await DoubleRatchet.encryptionAlgorithm
      .encryptString(message, secretKey: sharedSecretKeyAlice);
  cipher = SecretBox(cipher.cipherText, nonce: cipher.nonce, mac: cipher.mac);
  await cipher.checkMac(
      macAlgorithm: DoubleRatchet.encryptionAlgorithm.macAlgorithm,
      secretKey: sharedSecretKeyBob,
      aad: []);

  print(
      " nonce: ${cipher.nonce} mac: ${cipher.mac} bytes: ${cipher.cipherText}");
  final plain = await DoubleRatchet.encryptionAlgorithm
      .decryptString(cipher, secretKey: sharedSecretKeyBob);

  assert(plain == message);
  print(plain);
}

String crap() {
  return "${DateTime.now().microsecondsSinceEpoch} ${Random().nextDouble()}";
}

void e2eTest() async {
  final aliceSenderKeyPair = await DoubleRatchet.keyPairAlgorithm.newKeyPair();
  final bobSenderKeyPair = await DoubleRatchet.keyPairAlgorithm.newKeyPair();
  final aliceReceiverKeyPair =
      await DoubleRatchet.keyPairAlgorithm.newKeyPair();
  final bobReceiverKeyPair = await DoubleRatchet.keyPairAlgorithm.newKeyPair();

  final aliceSenderKey = await DoubleRatchet.keyPairAlgorithm.sharedSecretKey(
      keyPair: aliceSenderKeyPair,
      remotePublicKey: await bobReceiverKeyPair.extractPublicKey());

  final bobSenderKey = await DoubleRatchet.keyPairAlgorithm.sharedSecretKey(
      keyPair: bobSenderKeyPair,
      remotePublicKey: await aliceReceiverKeyPair.extractPublicKey());

  final aliceReceiverKey = await DoubleRatchet.keyPairAlgorithm.sharedSecretKey(
      keyPair: aliceReceiverKeyPair,
      remotePublicKey: await bobSenderKeyPair.extractPublicKey());

  final bobReceiverKey = await DoubleRatchet.keyPairAlgorithm.sharedSecretKey(
      keyPair: bobReceiverKeyPair,
      remotePublicKey: await aliceSenderKeyPair.extractPublicKey());

  final aliceDoubleRatchet =
      DoubleRatchet(senderKey: aliceSenderKey, receiverKey: aliceReceiverKey);
  final bobDoubleRatchet =
      DoubleRatchet(senderKey: bobSenderKey, receiverKey: bobReceiverKey);

  final aliceSentMessages = <String>[];
  final aliceReceivedMessages = <String>[];
  final bobSentMessages = <String>[];
  final bobReceivedMessages = <String>[];
  for (var i = 0; i < 10; i++) {
    final aliceOrBobisSender = Random().nextBool();
    if (aliceOrBobisSender) {
      final messages = Server.instance.readMessages("alice");
      for (final message in messages) {
        final decrypted = await aliceDoubleRatchet.decryptString(message);
        print("alice received $decrypted");
        aliceReceivedMessages.add(decrypted);
      }
    } else {
      final messages = Server.instance.readMessages("bob");
      for (final message in messages) {
        final decrypted = await bobDoubleRatchet.decryptString(message);
        print("bob received $decrypted");
        bobReceivedMessages.add(decrypted);
      }
    }
    final sendMessagesCount = Random().nextInt(5) + 1;
    for (int j = 0; j < sendMessagesCount; j++) {
      final message = crap();
      if (aliceOrBobisSender) {
        print("alice sending $message");
        final box = await aliceDoubleRatchet.encryptString(message);
        Server.instance.sendSecretBox(box, "bob");
        aliceSentMessages.add(message);
      } else {
        print("bob sending $message");
        final box = await bobDoubleRatchet.encryptString(message);
        Server.instance.sendSecretBox(box, "alice");
        bobSentMessages.add(message);
      }
    }
  }
  {
    {
      final messages = Server.instance.readMessages("alice");
      for (final message in messages) {
        final decrypted = await aliceDoubleRatchet.decryptString(message);
        print("alice received $decrypted");
        aliceReceivedMessages.add(decrypted);
      }
    }
    {
      final messages = Server.instance.readMessages("bob");
      for (final message in messages) {
        final decrypted = await bobDoubleRatchet.decryptString(message);
        print("bob received $decrypted");
        bobReceivedMessages.add(decrypted);
      }
    }
  }
  var aliceSentMessagesAreReceived =
      areListsEqual(aliceSentMessages, bobReceivedMessages);
  var bobSentMessagesAreReceived =
      areListsEqual(aliceReceivedMessages, bobSentMessages);

  assert(aliceSentMessagesAreReceived);
  assert(bobSentMessagesAreReceived);
  print(
      "alice sent: $aliceSentMessagesAreReceived, bob sent: $bobSentMessagesAreReceived");
}

class Server {
  static final instance = Server();

  Server();

  Map<String, List<String>> db = {};

  final jsonEncoder = JsonEncoder.withIndent(" ");
  void sendSecretBox(EncryptedMessage box, String to) {
    final s = json.encode(box.toSecretBox().toMap());
    if (db[to] != null) {
      db[to]!.add(s);
    } else {
      db[to] = [s];
    }
  }

  List<EncryptedMessage> readMessages(String from) {
    final list = db.remove(from);
    if (list != null) {
      return list
          .map((e) => EncryptedMessage.fromSecretBox(secretBoxfromJson(e)))
          .toList();
    }
    return <EncryptedMessage>[];
  }
}
