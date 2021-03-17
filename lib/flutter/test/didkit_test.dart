import 'package:flutter_test/flutter_test.dart';
import 'package:didkit/didkit.dart';
import 'dart:convert';
import 'package:uuid/uuid.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('getVersion', () async {
    expect(DIDKit.getVersion(), isInstanceOf<String>());
  });

  test('exceptions', () async {
    expect(() => DIDKit.issueCredential('', '', ''), throwsA(isInstanceOf<DIDKitException>()));
    expect(() => DIDKit.issuePresentation('', '', ''), throwsA(isInstanceOf<DIDKitException>()));
    expect(() => DIDKit.verifyCredential('', ''), throwsA(isInstanceOf<DIDKitException>()));
    expect(() => DIDKit.verifyPresentation('', ''), throwsA(isInstanceOf<DIDKitException>()));
  });

  test('generateEd25519Key', () async {
    expect(DIDKit.generateEd25519Key(), isInstanceOf<String>());
  });

  test('keyToDID', () async {
    final key = DIDKit.generateEd25519Key();
    final did = DIDKit.keyToDID('key', key);
    expect(did, isInstanceOf<String>());
  });

  test('verificationMethod', () async {
    final key = DIDKit.generateEd25519Key();
    final vm = DIDKit.keyToVerificationMethod('key', key);
    expect(vm, isInstanceOf<String>());
  });

  test('issueCredential, verifyCredential', () async {
    final key = DIDKit.generateEd25519Key();
    final did = DIDKit.keyToDID('key', key);
    final verificationMethod = DIDKit.keyToVerificationMethod('key', key);
    final options = {
        'proofPurpose': 'assertionMethod',
        'verificationMethod': verificationMethod
    };
    final credential = {
        '@context': 'https://www.w3.org/2018/credentials/v1',
        'id': 'http://example.org/credentials/3731',
        'type': ['VerifiableCredential'],
        'issuer': did,
        'issuanceDate': '2020-08-19T21:41:50Z',
        'credentialSubject': {
           'id': 'did:example:d23dd687a7dc6787646f2eb98d0'
        }
    };
    final vc = DIDKit.issueCredential(jsonEncode(credential), jsonEncode(options), key);

    final verifyOptions = {
        'proofPurpose': 'assertionMethod'
    };
    final verifyResult = jsonDecode(DIDKit.verifyCredential(vc, jsonEncode(verifyOptions)));
    expect(verifyResult['errors'], isEmpty);
  });

  test('issuePresentation, verifyPresentation', () async {
    final key = DIDKit.generateEd25519Key();
    final did = DIDKit.keyToDID('key', key);
    final verificationMethod = DIDKit.keyToVerificationMethod('key', key);
    final options = {
        'proofPurpose': 'authentication',
        'verificationMethod': verificationMethod
    };
    final presentation = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        'id': 'http://example.org/presentations/3731',
        'type': ['VerifiablePresentation'],
        'holder': did,
        'verifiableCredential': {
            '@context': 'https://www.w3.org/2018/credentials/v1',
            'id': 'http://example.org/credentials/3731',
            'type': ['VerifiableCredential'],
            'issuer': 'did:example:30e07a529f32d234f6181736bd3',
            'issuanceDate': '2020-08-19T21:41:50Z',
            'credentialSubject': {
                'id': 'did:example:d23dd687a7dc6787646f2eb98d0'
            }
        }
    };
    final vc = DIDKit.issuePresentation(jsonEncode(presentation), jsonEncode(options), key);

    final verifyOptions = {
        'proofPurpose': 'authentication'
    };
    final verifyResult = jsonDecode(DIDKit.verifyPresentation(vc, jsonEncode(verifyOptions)));
    expect(verifyResult['errors'], isEmpty);
  });

  test('resolveDID', () async {
    final key = DIDKit.generateEd25519Key();
    final did = DIDKit.keyToDID('key', key);
    final resolutionResult = jsonDecode(DIDKit.resolveDID(did, '{}'));
    expect(resolutionResult['didDocument'], isNotEmpty);
  });

  test('dereferenceDIDURL', () async {
    final key = DIDKit.generateEd25519Key();
    final verificationMethod = DIDKit.keyToVerificationMethod('key', key);
    final derefResult = jsonDecode(DIDKit.dereferenceDIDURL(verificationMethod, '{}'));
    expect(derefResult, isList);
  });

  test('DIDAuth', () async {
    final key = DIDKit.generateEd25519Key();
    final did = DIDKit.keyToDID('key', key);
    final verificationMethod = DIDKit.keyToVerificationMethod('key', key);

    final challenge = Uuid().v4();
    final proofOptions = jsonEncode({
      'proofPurpose': 'assertionMethod',
      'verificationMethod': verificationMethod,
      'challenge': challenge
    });
    final vp = DIDKit.DIDAuth(did, proofOptions, key);
    final verifyOptions = jsonEncode({
      'proofPurpose': 'assertionMethod',
      'challenge': challenge
    });
    final verification = DIDKit.verifyPresentation(vp, verifyOptions);
    final verifyResult = jsonDecode(verification);
    expect(verifyResult['errors'], isEmpty);
  });
}
