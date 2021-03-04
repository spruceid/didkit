import unittest
import didkit
import json
import tests
import uuid


class TestKeyMethods(unittest.TestCase):

    def setUp(self):
        tests.key = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I\",\"d\":\"n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI\"}"

    def testGetLibraryVersion(self):
        self.assertTrue(type(didkit.getVersion()) is str)

    def testGeneratesEd25519Key(self):
        key = json.loads(didkit.generateEd25519Key())
        self.assertIn("kty", key.keys())
        self.assertIn("crv", key.keys())
        self.assertIn("x", key.keys())
        self.assertIn("d", key.keys())

    def testKeyToDID(self):
        self.assertEqual(didkit.keyToDID("key", tests.key),
                         "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK"
                         )

    def testKeyToVerificationMethod(self):
        self.assertEqual(didkit.keyToVerificationMethod(
            "key", tests.key), "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK#z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK")


class TestCredentialMethods(unittest.TestCase):
    def setUp(self):
        tests.key = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I\",\"d\":\"n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI\"}"
        tests.did = didkit.keyToDID("key", tests.key)
        tests.verificationMethod = didkit.keyToVerificationMethod(
            "key", tests.key)
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

        tests.verificationMethod = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": tests.verificationMethod,
        }

    def testRaisesOnIssueWithEmptyObjects(self):
        with self.assertRaises(didkit.DIDKitException):
            didkit.issueCredential("{}", "{}", "{}")

    def testIssuesCredentials(self):
        credential = didkit.issueCredential(
            tests.credential.__str__().replace("'", '"'),
            tests.verificationMethod.__str__().replace("'", '"'),
            tests.key
        )

        verifyResult = json.loads(didkit.verifyCredential(
            credential.__str__().replace("'", '"'),
            "{\"proofPurpose\":\"assertionMethod\"}"
        ))

        self.assertEqual(len(verifyResult["errors"]), 0)


class TestPresentationMethods(unittest.TestCase):
    def setUp(self):
        tests.key = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I\",\"d\":\"n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI\"}"
        tests.did = didkit.keyToDID("key", tests.key)
        tests.verificationMethod = didkit.keyToVerificationMethod(
            "key", tests.key)
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

        tests.verificationPurpose = {
            "proofPurpose": "authentication",
            "verificationMethod": tests.verificationMethod,
        }

    def testRaisesOnPresentWithEmptyObjects(self):
        with self.assertRaises(didkit.DIDKitException):
            didkit.issuePresentation("{}", "{}", "{}")

    def testVerifyIssuedPresentation(self):
        presentation = didkit.issuePresentation(
            tests.presentation.__str__().replace("'", '"'),
            tests.verificationPurpose.__str__().replace("'", '"'),
            tests.key
        )

        verifyResult = json.loads(didkit.verifyPresentation(
            presentation.__str__().replace("'", '"'),
            tests.verificationPurpose.__str__().replace("'", '"')
        ))

        self.assertEqual(len(verifyResult["errors"]), 0)


class TestAuthMethods(unittest.TestCase):
    def setUp(self):
        tests.key = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I\",\"d\":\"n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI\"}"
        tests.did = didkit.keyToDID("key", tests.key)
        tests.verificationMethod = didkit.keyToVerificationMethod(
            "key",
            tests.key
        )

        tests.verificationPurpose = {
            "proofPurpose": "authentication",
            "verificationMethod": tests.verificationMethod,
            "challenge": uuid.uuid4().__str__()
        }

    def testRaisesOnPresentWithEmptyObjects(self):
        with self.assertRaises(didkit.DIDKitException):
            didkit.DIDAuth("", "{}", "{}")

    def testIssueAndVerifyDIDAuthVerifiablePresentation(self):
        presentation = didkit.DIDAuth(
            tests.did.__str__().replace("'", '"'),
            tests.verificationPurpose.__str__().replace("'", '"'),
            tests.key
        )

        verifyResult = json.loads(didkit.verifyPresentation(
            presentation,
            tests.verificationPurpose.__str__().replace("'", '"')
        ))

        self.assertEqual(len(verifyResult["errors"]), 0)


if __name__ == '__main__':
    unittest.main()
