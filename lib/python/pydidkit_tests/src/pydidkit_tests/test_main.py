import pytest
import pydidkit
import json
from uuid import uuid4

JWK = '{"kty":"OKP","crv":"Ed25519","x":"PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I","d":"n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI"}'


class TestKeyMethods:
    def test_get_library_version(self):
        assert type(pydidkit.get_version()) is str

    def test_generates_ed25519_key(self):
        key = json.loads(pydidkit.generate_ed25519_key())
        assert "kty" in key.keys()
        assert "crv" in key.keys()
        assert "x" in key.keys()
        assert "d" in key.keys()

    def test_key_to_did(self):
        assert (
            pydidkit.key_to_did("key", JWK)
            == "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK"
        )

    @pytest.mark.asyncio
    async def test_key_to_verification_method(self):
        assert (
            await pydidkit.key_to_verification_method("key", JWK)
            == "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK#z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK"
        )


class TestCredentialMethods:
    did = pydidkit.key_to_did("key", JWK)
    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "issuer": did,
        "issuanceDate": "2020-08-19T21:41:50Z",
        "credentialSubject": {
            "id": "did:example:d23dd687a7dc6787646f2eb98d0",
        },
    }
    options = {}

    @pytest.fixture
    async def setup(self):
        vm = await pydidkit.key_to_verification_method("key", JWK)
        self.options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": vm,
        }

    @pytest.mark.asyncio
    async def test_raises_on_issue_with_empty_objects(self):
        with pytest.raises(ValueError):
            await pydidkit.issue_credential("{}", "{}", "{}")

    @pytest.mark.asyncio
    async def test_issues_credentials(self):
        credential = await pydidkit.issue_credential(
            json.dumps(self.credential), json.dumps(self.options), JWK
        )

        result = json.loads(
            await pydidkit.verify_credential(
                credential, '{"proofPurpose":"assertionMethod"}'
            )
        )

        assert not result["errors"]


class TestPresentationMethods:
    did = pydidkit.key_to_did("key", JWK)
    presentation = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "http://example.org/presentations/3731",
        "type": ["VerifiablePresentation"],
        "holder": did,
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
    options = {}

    @pytest.fixture
    async def setup(self):
        self.vm = await pydidkit.key_to_verification_method("key", JWK)
        self.options = {
            "proofPurpose": "authentication",
            "verificationMethod": self.vm,
        }

    @pytest.mark.asyncio
    async def test_raises_on_present_with_empty_objects(self):
        with pytest.raises(ValueError):
            await pydidkit.issue_presentation("{}", "{}", "{}")

    @pytest.mark.asyncio
    async def test_verify_issued_presentation(self):
        presentation = await pydidkit.issue_presentation(
            json.dumps(self.presentation), json.dumps(self.options), JWK
        )
        result = json.loads(
            await pydidkit.verify_presentation(
                presentation, json.dumps(self.options)
            )
        )

        assert not result["errors"]


class TestAuthMethods:
    did = pydidkit.key_to_did("key", JWK)
    options = {}

    @pytest.fixture
    async def setup(self):
        vm = await pydidkit.key_to_verification_method("key", JWK)
        self.options = {
            "proofPurpose": "authentication",
            "verificationMethod": vm,
            "challenge": str(uuid4()),
        }

    @pytest.mark.asyncio
    async def test_raises_on_present_with_empty_objects(self):
        with pytest.raises(ValueError):
            await pydidkit.did_auth("", "{}", "{}")

    @pytest.mark.asyncio
    async def test_issue_and_verify_didauth_verifiable_presentation(self):
        presentation = await pydidkit.did_auth(self.did, json.dumps(self.options), JWK)

        result = json.loads(
            await pydidkit.verify_presentation(presentation, json.dumps(self.options))
        )

        assert not result["errors"]
