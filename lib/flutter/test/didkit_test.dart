import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:didkit/didkit.dart';
import 'dart:convert';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('getVersion', () async {
    expect(DIDKit.getVersion(), isInstanceOf<String>());
  });

  final jsonCredential = '{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"id":"urn:uuid:f493fd1c-6520-4ef8-ac20-e66070abf234","type":["VerifiableCredential"],"credentialSubject":{"id":"did:key:z6Mkro26JhbjLrznJEzvGsR2Dy4g4dFRYdkWTt2HgRYhpCc2","alumniOf":"root"},"issuer":"did:key:z6MkgAz2ZaJSmJ6NJ1xsohGq7syi41V8LLDG6JTSN2GA2JSc","issuanceDate":"2021-02-09T16:28:56Z","proof":{"type":"Ed25519Signature2018","proofPurpose":"assertionMethod","verificationMethod":"did:key:z6MkgAz2ZaJSmJ6NJ1xsohGq7syi41V8LLDG6JTSN2GA2JSc#z6MkgAz2ZaJSmJ6NJ1xsohGq7syi41V8LLDG6JTSN2GA2JSc","created":"2021-02-09T16:28:56.344Z","jws":"eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..4QjG_XuduJiBFbfkacHbvQ_L-pxmrHbsDOvNZWq4rkd1xnBb7-TtM7r_Yn0ms4thMRJ3MuIOMDoeTWFbFE6ZAA"}}';

  test('verifyCredential no opts', () async {
    final verification = await DIDKit.verifyCredential(
      jsonCredential,
      jsonEncode({}),
    );

    final verifyResult = jsonDecode(verification);
    expect(verifyResult['errors'], isEmpty);
  });

  test('verifyCredential proofPurpose', () async {
    final verification = await DIDKit.verifyCredential(
      jsonCredential,
      jsonEncode({'proofPurpose': 'assertionMethod'}),
    );

    final verifyResult = jsonDecode(verification);
    expect(verifyResult['errors'], isEmpty);
  });

  test('resolveDID', () async {
    final key = DIDKit.generateEd25519Key();
    final did = DIDKit.keyToDID("key", key);
    final resolutionResult = jsonDecode(DIDKit.resolveDID(did, "{}"));
    expect(resolutionResult['didDocument'], isNotEmpty);
  });

  test('dereferenceDIDURL', () async {
    final key = DIDKit.generateEd25519Key();
    final verificationMethod = DIDKit.keyToVerificationMethod("key", key);
    final derefResult = jsonDecode(DIDKit.dereferenceDIDURL(verificationMethod, "{}"));
    expect(derefResult, isList);
  });
}
