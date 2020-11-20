#!/bin/sh
# Example script using DIDKit for key generation, credential/presentation
# issuance and verification.

# Exit if anything fails
set -e

# Pretty-print JSON
print_json() {
	file=${1?file}
	if command -v jq >/dev/null 2>&1; then
		jq . "$file" || cat "$file"
	elif command -v json_pp >/dev/null 2>&1; then
		json_pp < "$file" || cat "$file"
	else
		cat "$file"
	fi
}

# Run in source directory
cd "$(dirname "$0")"

# Build didkit CLI
cargo build -p didkit-cli

# Get didkit in $PATH
export PATH=$PWD/../../target/debug:$PATH

# Create a keypair if needed
if [ -e key.jwk ]; then
	echo 'Using existing keypair.'
else
	didkit generate-ed25519-key > key.jwk
	echo 'Generated keypair.'
fi
echo

# Get DID (did:key) for keypair
did=$(didkit key-to-did-key -k key.jwk)
printf 'DID: %s\n\n' "$did"

# Prepare credential for issuing
cat > credential-unsigned.jsonld <<EOF
{
	"@context": "https://www.w3.org/2018/credentials/v1",
	"id": "http://example.org/credentials/3731",
	"type": ["VerifiableCredential"],
	"issuer": "$did",
	"issuanceDate": "2020-08-19T21:41:50Z",
	"credentialSubject": {
		"id": "did:example:d23dd687a7dc6787646f2eb98d0"
	}
}
EOF

# Issue verifiable credential
didkit vc-issue-credential \
	-k key.jwk \
	-v "$did" \
	-p assertionMethod \
	< credential-unsigned.jsonld \
	> credential-signed.jsonld
echo 'Issued verifiable credential:'
print_json credential-signed.jsonld
echo

# Verify verifiable credential
if ! didkit vc-verify-credential \
	-v "$did" \
	-p assertionMethod \
	< credential-signed.jsonld \
	> credential-verify-result.json
then
	echo 'Unable to verify credential:'
	print_json credential-verify-result.json
	exit 1
fi
echo 'Verified verifiable credential:'
print_json credential-verify-result.json
echo

# Create presentation embedding verifiable credential
cat > presentation-unsigned.jsonld <<EOF
{
	"@context": ["https://www.w3.org/2018/credentials/v1"],
	"id": "http://example.org/presentations/3731",
	"type": ["VerifiablePresentation"],
	"holder": "$did",
	"verifiableCredential": $(cat credential-signed.jsonld)
}
EOF

# Issue verifiable presentation
didkit vc-issue-presentation \
	-k key.jwk \
	-v "$did" \
	-p authentication \
	< presentation-unsigned.jsonld \
	> presentation-signed.jsonld
echo 'Issued verifiable presentation:'
print_json presentation-signed.jsonld
echo

# Verify verifiable presentation
if ! didkit vc-verify-presentation \
	-v "$did" \
	-p authentication \
	< presentation-signed.jsonld \
	> presentation-verify-result.json
then
	echo 'Unable to verify presentation:'
	print_json presentation-verify-result.json
	exit 1
fi
echo 'Verified verifiable presentation:'
print_json presentation-verify-result.json
echo

echo Done
