#!/bin/sh
# This is an example shell script using DIDKit's HTTP server for
# credential/presentation issuance and verification.
# DIDKit is used for key generation.

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

# Build the didkit CLI program and HTTP server
cargo build -p didkit-cli -p didkit-http

# Adjust $PATH to include the didkit executable.
export PATH=$PWD/../../target/debug:$PATH

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
printf 'DID: %s\n' "$did"

# Get verificationMethod for keypair.
# This is used to identify the key in linked data proofs.
verification_method=$(didkit key-to-verification-method "$did_method" -k key.jwk)
printf 'verificationMethod: %s\n' "$verification_method"

# Start the HTTP server
didkit-http -p 9999 -k key.jwk & pid=$!
didkit_url=http://localhost:9999

# Stop the HTTP server when the shell script exits
trap "kill $pid" 1 2 15 EXIT

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
if ! curl -fsS $didkit_url/credentials/issue \
	-H 'Content-Type: application/json' \
	-o credential-signed \
	-d @- <<EOF
{
  "credential": $(cat credential-unsigned.jsonld),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "assertionMethod",
    "proofFormat": "$vc_proof_format"
  }
}
EOF
then
	echo 'Unable to issue credential.'
	exit 1
fi

echo 'Issued verifiable credential:'
if [ "$vc_proof_format" = jwt ]; then
	cat credential-signed
else
	print_json credential-signed
fi
echo

# Encode credential as JSON for presenting.
if [ "$vc_proof_format" = jwt ]; then
	echo -n '"'
	cat credential-signed
	echo -n '"'
else
	cat credential-signed
fi > credential-signed.json

# Verify verifiable credential.
# We pass the newly-issued verifiable credential back to didkit for
# verification using the given verification method and proof purpose. DIDKit
# outputs the verification result as JSON. If verification is successful, the
# command completes successfully (returns exit code 0).
if ! curl -fsS $didkit_url/credentials/verify \
	-H 'Content-Type: application/json' \
	-o credential-verify-result.json \
	-d @- <<EOF
{
  "verifiableCredential": $(cat credential-signed.json),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "assertionMethod",
    "proofFormat": "$vc_proof_format"
  }
}
EOF
then
	echo 'Unable to verify credential.'
	exit 1
fi
echo 'Verified verifiable credential:'
print_json credential-verify-result.json
echo

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
if ! curl -fsS $didkit_url/credentials/prove \
	-H 'Content-Type: application/json' \
	-o presentation-signed \
	-d @- <<EOF
{
  "presentation": $(cat presentation-unsigned.jsonld),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "authentication",
    "proofFormat": "$vp_proof_format"
  }
}
EOF
then
	echo 'Unable to issue presentation.'
	cat presentation-signed
	exit 1
fi
echo 'Issued verifiable presentation:'
if [ "$vp_proof_format" = jwt ]; then
	cat presentation-signed
else
	print_json presentation-signed
fi
echo

# Encode presentation as JSON for verification.
if [ "$vp_proof_format" = jwt ]; then
	echo -n '"'
	cat presentation-signed
	echo -n '"'
else
	cat presentation-signed
fi > presentation-signed.json

# Verify verifiable presentation.
# Pass the verifiable presentation back to didkit for verification.
# Examine the verification result JSON.
if ! curl -fsS $didkit_url/presentations/verify \
	-H 'Content-Type: application/json' \
	-o presentation-verify-result.json \
	-d @- <<EOF
{
  "verifiablePresentation": $(cat presentation-signed.json),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "authentication",
    "proofFormat": "$vp_proof_format"
  }
}
EOF
then
	echo 'Unable to verify presentation.'
	exit 1
fi
# TODO: allow either format if proofFormat is unset?
echo 'Verified verifiable presentation:'
print_json presentation-verify-result.json
echo

# Resolve a DID to a DID Document.
if ! curl -fsS "$didkit_url/identifiers/$did" \
	-o did.json
then
	echo 'Unable to resolve DID.'
	exit 1
fi
echo 'Resolved DID to DID document:'
print_json did.json
echo

# Dereference a DID URL.
# URL-encode verificationMethod DID URL
vm_enc=$(printf %s "$verification_method" | sed 's/#/%23/g')
if ! curl -fsS "$didkit_url/identifiers/$vm_enc" \
	-o vm.json
then
	echo 'Unable to resolve DID.'
	exit 1
fi
echo 'Dereferenced DID URL for verification method:'
print_json vm.json
echo

echo Done
