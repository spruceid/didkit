#!/bin/sh
# Example script using DIDKit for key generation, credential/presentation
# issuance and verification.

# Exit if anything fails
set -e

# Pretty-print JSON
print_json() {
	file=${1?file}
	if command -v jq >/dev/null 2>&1; then
		jq . "$file"
	elif command -v json_pp >/dev/null 2>&1; then
		json_pp "$file"
	else
		cat "$file"
	fi
}

# Run in source directory
cd "$(dirname "$0")"

# Build didkit CLI
cargo build -p didkit_cli

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
didkit vc-verify-credential \
	-p assertionMethod \
	< credential-signed.jsonld \
	> credential-verify-result.json
echo 'Verified verifiable credential:'
print_json credential-verify-result.json
echo

# Create presentation embedding verifiable credential
{
	echo '{"verifiableCredential": '
	cat credential-signed.jsonld
	echo ','
	tail +2 presentation-unsigned.jsonld
} > presentation-unsigned-constructed.jsonld
echo 'Created presentation.'
echo

# Issue verifiable presentation
didkit vc-issue-presentation \
	-k key.jwk \
	-v "$did" \
	-p authentication \
	< presentation-unsigned-constructed.jsonld \
	> presentation-signed.jsonld
echo 'Issued verifiable presentation:'
print_json presentation-signed.jsonld
echo

# Verify verifiable presentation
didkit vc-verify-presentation \
	-p authentication \
	< presentation-signed.jsonld \
	> presentation-verify-result.json
echo 'Verified verifiable presentation:'
print_json presentation-verify-result.json
