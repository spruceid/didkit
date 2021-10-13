import unittest
import didkit
import json
import tests
import uuid


class TestKeyMethods(unittest.TestCase):
    def setUp(self):
        tests.key = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I\",\"d\":\"n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI\"}"

    def testGetLibraryVersion(self):
        self.assertTrue(type(didkit.get_version()) is str)

    def testGeneratesEd25519Key(self):
        key = json.loads(didkit.generate_ed25519_key())
        self.assertIn("kty", key.keys())
        self.assertIn("crv", key.keys())
        self.assertIn("x", key.keys())
        self.assertIn("d", key.keys())

    def testKeyToDID(self):
        self.assertEqual(
            didkit.key_to_did("key", tests.key),
            "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK")

    def testKeyToVerificationMethod(self):
        self.assertEqual(
            didkit.key_to_verification_method("key", tests.key),
            "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK#z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK"
        )


class TestCredentialMethods(unittest.TestCase):
    def setUp(self):
        tests.key = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I\",\"d\":\"n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI\"}"
        tests.did = didkit.key_to_did("key", tests.key)
        tests.vm = didkit.key_to_verification_method("key", tests.key)
        tests.credential = {
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": tests.did,
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0",
            },
        }

        tests.options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": tests.vm,
        }

    def testRaisesOnIssueWithEmptyObjects(self):
        with self.assertRaises(didkit.DIDKitException):
            didkit.issue_credential("{}", "{}", "{}")

    def testIssuesCredentials(self):
        credential = didkit.issue_credential(
            tests.credential.__str__().replace("'", '"'),
            tests.options.__str__().replace("'", '"'), tests.key)

        result = json.loads(
            didkit.verify_credential(credential.__str__().replace("'", '"'),
                                     "{\"proofPurpose\":\"assertionMethod\"}"))

        self.assertFalse(result["errors"])


class TestPresentationMethods(unittest.TestCase):
    def setUp(self):
        tests.key = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I\",\"d\":\"n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI\"}"
        tests.did = didkit.key_to_did("key", tests.key)
        tests.vm = didkit.key_to_verification_method("key", tests.key)
        tests.presentation = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": "http://example.org/presentations/3731",
            "type": ["VerifiablePresentation"],
            "holder": tests.did,
            "verifiableCredential": {
                "@context": "https://www.w3.org/2018/credentials/v1",
                "id": "http://example.org/credentials/3731",
                "type": ["VerifiableCredential"],
                "issuer": "did:example:30e07a529f32d234f6181736bd3",
                "issuanceDate": "2020-08-19T21:41:50Z",
                "credentialSubject": {
                    "id": "did:example:d23dd687a7dc6787646f2eb98d0",
                },
            },
        }

        tests.options = {
            "proofPurpose": "authentication",
            "verificationMethod": tests.vm,
        }

    def testRaisesOnPresentWithEmptyObjects(self):
        with self.assertRaises(didkit.DIDKitException):
            didkit.issue_presentation("{}", "{}", "{}")

    def testVerifyIssuedPresentation(self):
        presentation = didkit.issue_presentation(
            tests.presentation.__str__().replace("'", '"'),
            tests.options.__str__().replace("'", '"'), tests.key)

        result = json.loads(
            didkit.verify_presentation(presentation.__str__().replace(
                "'", '"'),
                                       tests.options.__str__().replace(
                                           "'", '"')))

        self.assertFalse(result["errors"])


class TestAuthMethods(unittest.TestCase):
    def setUp(self):
        tests.key = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I\",\"d\":\"n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI\"}"
        tests.did = didkit.key_to_did("key", tests.key)
        tests.vm = didkit.key_to_verification_method("key", tests.key)

        tests.options = {
            "proofPurpose": "authentication",
            "verificationMethod": tests.vm,
            "challenge": uuid.uuid4().__str__()
        }

    def testRaisesOnPresentWithEmptyObjects(self):
        with self.assertRaises(didkit.DIDKitException):
            didkit.did_auth("", "{}", "{}")

    def testIssueAndVerifyDIDAuthVerifiablePresentation(self):
        presentation = didkit.did_auth(tests.did.__str__().replace("'", '"'),
                                       tests.options.__str__().replace(
                                           "'", '"'), tests.key)

        result = json.loads(
            didkit.verify_presentation(presentation,
                                       tests.options.__str__().replace(
                                           "'", '"')))

        self.assertFalse(result["errors"])


if __name__ == '__main__':
    unittest.main()
