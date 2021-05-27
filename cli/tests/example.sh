#!/bin/sh
# This is an example shell script using DIDKit for key generation,
# credential/presentation issuance and verification.

# Exit if any command in the script fails.
set -e

# Allow issuing using a DID method other than did:key
did_method=${DID_METHOD:-key}
# More info about did:key: https://w3c-ccg.github.io/did-method-key/

# Allow setting proof format using environmental variables.
proof_format=${PROOF_FORMAT:-ldp}
vc_proof_format=${VC_PROOF_FORMAT:-$proof_format}
vp_proof_format=${VP_PROOF_FORMAT:-$proof_format}

# Pretty-print JSON using jq or json_pp if available.
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

# Run the rest of this script in its source directory.
cd "$(dirname "$0")"

# Build the didkit CLI program
cargo build -p didkit-cli

# Adjust $PATH to include the didkit executable.
export PATH="$PWD/../../target/debug:$PATH"

# Create a ed25119 keypair if needed.
if [ -e key.jwk ]; then
	echo 'Using existing keypair.'
else
	didkit generate-ed25519-key > key.jwk
	echo 'Generated keypair.'
fi
echo

# Get the keypair's DID.
did=$(didkit key-to-did "$did_method" -k key.jwk)
printf 'DID: %s\n\n' "$did"

# Get verificationMethod for keypair.
# This is used to identify the key in linked data proofs.
verification_method=$(didkit key-to-verification-method "$did_method" -k key.jwk)
printf 'verificationMethod: %s\n\n' "$verification_method"

# Prepare credential for issuing.
# In this example credential, the issuance date, id, and credential subject id
# are arbitrary. For more info about what these properties mean, see the
# Verifiable Credentials Data Model: https://w3c.github.io/vc-data-model/
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

# Issue the verifiable credential.
# Ask didkit to issue a verifiable credential using the given keypair file,
# verification method, and proof purpose, passing the unsigned credential on
# standard input. DIDKit creates a linked data proof to add to the credential,
# and outputs the resulting newly-issued verifiable credential on standard
# output, which we save to a file.
didkit vc-issue-credential \
	-k key.jwk \
	-v "$verification_method" \
	-p assertionMethod \
	-f "$vc_proof_format" \
	< credential-unsigned.jsonld \
	> credential-signed
echo 'Issued verifiable credential:'
if [ "$vc_proof_format" = jwt ]; then
	cat credential-signed
else
	print_json credential-signed
fi
echo

# Verify verifiable credential.
# We pass the newly-issued verifiable credential back to didkit for
# verification using the given verification method and proof purpose. DIDKit
# outputs the verification result as JSON. If verification is successful, the
# command completes successfully (returns exit code 0).
if ! didkit vc-verify-credential \
	-v "$verification_method" \
	-p assertionMethod \
	-f "$vc_proof_format" \
	< credential-signed \
	> credential-verify-result.json
then
	echo 'Unable to verify credential:'
	print_json credential-verify-result.json
	exit 1
fi
echo 'Verified verifiable credential:'
print_json credential-verify-result.json
echo

# Encode credential as JSON for presenting.
if [ "$vc_proof_format" = jwt ]; then
	echo -n '"'
	cat credential-signed
	echo -n '"'
else
	cat credential-signed
fi > credential-signed.json

# Create presentation embedding verifiable credential.
# Prepare to present the verifiable credential by wrapping it in a
# Verifiable Presentation. The id here is an arbitrary URL for example purposes.
cat > presentation-unsigned.jsonld <<EOF
{
	"@context": ["https://www.w3.org/2018/credentials/v1"],
	"id": "http://example.org/presentations/3731",
	"type": ["VerifiablePresentation"],
	"holder": "$did",
	"verifiableCredential": $(cat credential-signed.json)
}
EOF

# Issue verifiable presentation.
# Pass the unsigned verifiable presentation to didkit to be issued as a
# verifiable presentation. DIDKit signs the presentation with a linked data
# proof, using the given keypair, verification method and proof type. We save
# the resulting newly created verifiable presentation to a file.
didkit vc-issue-presentation \
	-k key.jwk \
	-v "$verification_method" \
	-p authentication \
	-f "$vp_proof_format" \
	< presentation-unsigned.jsonld \
	> presentation-signed
echo 'Issued verifiable presentation:'
if [ "$vp_proof_format" = jwt ]; then
	cat presentation-signed
else
	print_json presentation-signed
fi
echo

# Verify verifiable presentation.
# Pass the verifiable presentation back to didkit for verification.
# Examine the verification result JSON.
if ! didkit vc-verify-presentation \
	-v "$verification_method" \
	-p authentication \
	-f "$vp_proof_format" \
	< presentation-signed \
	> presentation-verify-result.json
then
	echo 'Unable to verify presentation:'
	print_json presentation-verify-result.json
	exit 1
fi
echo 'Verified verifiable presentation:'
print_json presentation-verify-result.json
echo

# Resolve a DID.
if ! didkit did-resolve "$did" > did.json
then
	echo 'Unable to resolve DID.'
	exit 1
fi
echo 'Resolved DID to DID document:'
print_json did.json

# Dereference a DID URL
if ! didkit did-dereference "$verification_method" > vm.json
then
	echo 'Unable to dereference DID URL.'
	exit 1
fi
echo 'Dereferenced DID URL for verification method:'
print_json vm.json

# Authenticate with a DID
if ! challenge=$(awk 'BEGIN { srand(); print rand() }')
then
	echo 'Unable to create challenge.'
	exit 1
fi
if ! didkit did-auth \
	-k key.jwk \
	-h "$did" \
	-p authentication \
	-C "$challenge" \
	-v "$verification_method" \
	-f "$vp_proof_format" \
	> auth
then
	echo 'Unable to create DIDAuth response'
	exit 1
fi

echo 'Generated DIDAuth verifiable presentation:'
if [ "$vp_proof_format" = jwt ]; then
	cat auth
else
	print_json auth
fi
echo

# Verify DID auth
if ! didkit vc-verify-presentation \
	-p authentication \
	-C "$challenge" \
	-f "$vp_proof_format" \
	< auth \
	> auth-verify-result.json
then
	echo 'Unable to verify DIDAuth presentation:'
	print_json auth-verify-result.json
	exit 1
fi
echo 'Verified DIDAuth verifiable presentation:'
print_json auth-verify-result.json

echo Done
