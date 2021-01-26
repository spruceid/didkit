---
id: example--core-functions-in-curl
title: Bash Script - Core Functions (HTTP)
---

### Introduction

This is an example shell script using all the core functions of DIDKit-CLI: key generation, credential/presentation issuance and verification.

*Note: This script is meant to be in a DIDKit-CLI source directory. See the complete script below for setup details.*

### Start with a keypair
DIDKit can generate a unique ed25119 keypair from entropy. Alternately, you can provide a static key locally.

```bash
if [ -e issuer_key.jwk ]; then
	echo 'Using existing keypair.'
else
	didkit generate-ed25519-key > issuer_key.jwk
	echo 'Generated keypair.'
fi

echo
```

### Generate a DID:Key document 
This document gets wrapped around the keypair generated (or passed) in the previous step. For more context on the DID:key method, see the [specification](https://w3c-ccg.github.io/did-method-key/).

```bash
did=$(didkit key-to-did-key -k issuer_key.jwk)
printf 'DID: %s\n\n' "$did"
```

### Define verificationMethod for keypair.
This is used to identify the key in linked data proofs. Verifiers of such proofs query a DID found in a credential based on what [registered] proof type (i.e., what kind of signatures) it needs key material to verify.

```bash
verification_method=$(didkit key-to-verification-method -k issuer_key.jwk)
printf 'verificationMethod: %s\n\n' "$verification_method"
```

### Start HTTP Server

```bash
didkit-http -p 9999 -k key.jwk & pid=$!
didkit_url=http://localhost:9999
```

### Stop HTTP Server

```bash
trap "kill $pid" 1 2 15 EXIT
```

### Prepare credential for issuing.
In this example credential, the issuance date, id, and credential subject id are arbitrary, but in real-world usage these are diverse and critical properties. For more info about what these properties mean, see the Verifiable Credentials Data Model [specification](https://w3c.github.io/vc-data-model/)

```bash
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
```

### Issue the verifiable credential.
1. Ask didkit to issue a verifiable credential using the given keypair file, verification method, and proof purpose, passing the unsigned credential on standard input. 
2. DIDKit creates a linked data proof to add to the credential, and outputs the resulting newly-issued verifiable credential on standard output, which we save to a file.

```bash
if ! curl -fsS $didkit_url/issue/credentials \
	-H 'Content-Type: application/json' \
	-o credential-signed.jsonld \
	-d @- <<EOF
{
  "credential": $(cat credential-unsigned.jsonld),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "assertionMethod"
  }
}
EOF
then
	echo 'Unable to issue credential.'
	exit 1
fi

echo 'Issued verifiable credential:'
print_json credential-signed.jsonld
echo
```

### Verify a verifiable credential.
* We pass the newly-issued verifiable credential back to didkit for verification using the given verification method and proof purpose. 
* DIDKit outputs the verification result as JSON. 
* If verification is successful, the command completes successfully (returns exit code 0).

```bash
if ! curl -fsS $didkit_url/verify/credentials \
	-H 'Content-Type: application/json' \
	-o credential-verify-result.json \
	-d @- <<EOF
{
  "verifiableCredential": $(cat credential-signed.jsonld),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "assertionMethod"
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
```

### Create presentation embedding verifiable credential.
* Prepare to present the verifiable credential by wrapping it in a Verifiable Presentation. 
* The id here is an arbitrary URL for example purposes; VPs are often but not always uniquely identified, whether by identifiers, URLs, or URIs.

```bash
cat > presentation-unsigned.jsonld <<EOF
{
	"@context": ["https://www.w3.org/2018/credentials/v1"],
	"id": "http://example.org/presentations/3731",
	"type": ["VerifiablePresentation"],
	"holder": "$did",
	"verifiableCredential": $(cat credential-signed.jsonld)
}
EOF
```

### Issue verifiable presentation.
* Pass the unsigned verifiable presentation to DIDKit to be issued as a verifiable presentation. * DIDKit signs the presentation with a linked data proof, using the given keypair, verification method and proof type. 
* We save the resulting newly created verifiable presentation to a file.

:::note 
In most use-cases, the `holder` field contains a DID or other identifier verifiably linked to the key material signing the presentation, which has some relationship to the credential(s) being presented. The classic example is a fresh and interactive proof of being the [human] subject identified by a credential, but there are many VP use-cases as well.  This may be a manual, consented, unique and interactive identity assurance operation, but it can also be an assurance of the identity of a machine or a legal entity, operated by an API call or an automation carried out by a fiduciary/trusted piece of software, etc.

In these examples, the keys representing the two parties are stored in expressive filenames, 'issuer_key' and 'holder_key'. There are, however, no differences between these keys, and the JWK filenames were chosen simply to clarify the example; there are no restrictions on them.
:::

```bash
if ! curl -fsS $didkit_url/prove/presentations \
	-H 'Content-Type: application/json' \
	-o presentation-signed.jsonld \
	-d @- <<EOF
{
  "presentation": $(cat presentation-unsigned.jsonld),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "authentication"
  }
}
EOF
then
	echo 'Unable to issue presentation.'
	exit 1
fi
echo 'Issued verifiable presentation:'
print_json presentation-signed.jsonld
echo
```

### Verify verifiable presentation.
* Pass the verifiable presentation back to didkit for verification.
* Examine the verification result JSON.

```bash
if ! curl -fsS $didkit_url/verify/credentials \
	-H 'Content-Type: application/json' \
	-o credential-verify-result.json \
	-d @- <<EOF
{
  "verifiableCredential": $(cat credential-signed.jsonld),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "assertionMethod"
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

````

### Appendix: whole script without comments

Also available on Github as
[/cli/tests/example.sh](https://github.com/spruceid/didkit/blob/main/http/tests/example.sh)

```bash
#!/bin/sh
# This is an example shell script using DIDKit's HTTP server for
# credential/presentation issuance and verification.
# DIDKit is used for key generation.

# Exit if any command in the script fails.
set -e

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

# Get the keypair's did:key DID.
# More info about did:key: https://w3c-ccg.github.io/did-method-key/
did=$(didkit key-to-did-key -k key.jwk)
printf 'DID: %s\n' "$did"

# Get verificationMethod for keypair.
# This is used to identify the key in linked data proofs.
verification_method=$(didkit key-to-verification-method -k key.jwk)
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
if ! curl -fsS $didkit_url/issue/credentials \
	-H 'Content-Type: application/json' \
	-o credential-signed.jsonld \
	-d @- <<EOF
{
  "credential": $(cat credential-unsigned.jsonld),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "assertionMethod"
  }
}
EOF
then
	echo 'Unable to issue credential.'
	exit 1
fi

echo 'Issued verifiable credential:'
print_json credential-signed.jsonld
echo

# Verify verifiable credential.
# We pass the newly-issued verifiable credential back to didkit for
# verification using the given verification method and proof purpose. DIDKit
# outputs the verification result as JSON. If verification is successful, the
# command completes successfully (returns exit code 0).
if ! curl -fsS $didkit_url/verify/credentials \
	-H 'Content-Type: application/json' \
	-o credential-verify-result.json \
	-d @- <<EOF
{
  "verifiableCredential": $(cat credential-signed.jsonld),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "assertionMethod"
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
	"verifiableCredential": $(cat credential-signed.jsonld)
}
EOF

# Issue verifiable presentation.
# Pass the unsigned verifiable presentation to didkit to be issued as a
# verifiable presentation. DIDKit signs the presentation with a linked data
# proof, using the given keypair, verification method and proof type. We save
# the resulting newly created verifiable presentation to a file.
if ! curl -fsS $didkit_url/prove/presentations \
	-H 'Content-Type: application/json' \
	-o presentation-signed.jsonld \
	-d @- <<EOF
{
  "presentation": $(cat presentation-unsigned.jsonld),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "authentication"
  }
}
EOF
then
	echo 'Unable to issue presentation.'
	exit 1
fi
echo 'Issued verifiable presentation:'
print_json presentation-signed.jsonld
echo

# Verify verifiable presentation.
# Pass the verifiable presentation back to didkit for verification.
# Examine the verification result JSON.
if ! curl -fsS $didkit_url/verify/presentations \
	-H 'Content-Type: application/json' \
	-o presentation-verify-result.json \
	-d @- <<EOF
{
  "verifiablePresentation": $(cat presentation-signed.jsonld),
  "options": {
    "verificationMethod": "$verification_method",
    "proofPurpose": "authentication"
  }
}
EOF
then
	echo 'Unable to verify presentation.'
	exit 1
fi
echo 'Verified verifiable presentation:'
print_json presentation-verify-result.json
echo

echo Done
```