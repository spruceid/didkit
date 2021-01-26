---
id: "example--batch-generation"
title: Bash Script - Batch Generation & Verification
---

### Introduction

This shell script can be used to quickly generate a large volume of VCs for testing purposes.  The generated VCs use the bare-minimum schema and contain essentially nothing aside from a unique UUID each, in the `id` field.  

To generate these VC ids, they use the commonplace [uuidgen](https://stackoverflow.com/questions/56172946/how-to-generate-a-uuid-in-shell-script) command.  For more realistic sample VCs, simply start with a credential definition from a real-world context, and populate values for all the fields, such as names and addresses, with command-line tools or spreadsheets of dummy data.

## Batch Issuance Setup 

```bash
#!/bin/sh

# Exit if any command in this script fails.
set -e

if [ -e issuer_key.jwk ]; then
	echo 'Using existing keypair.'
else
	didkit generate-ed25519-key > issuer_key.jwk
	echo 'Generated keypair.'
fi
issuer=$(didkit key-to-did-key -k issuer_key.jwk)
printf 'Issuer DID: %s\n' "$issuer"
issuer_vm=$(didkit key-to-verification-method -k issuer_key.jwk)
printf 'Issuer verification method: %s\n' "$issuer_vm"
```

### Define generation function
```bash
generate_credential() {
	didkit vc-issue-credential \
		-k issuer_key.jwk \
		-v "$issuer_vm" \
		-p assertionMethod <<-EOF
	{
		"@context": "https://www.w3.org/2018/credentials/v1",
		"id": "uuid:$(uuidgen)",
		"type": ["VerifiableCredential"],
		"issuer": "$issuer",
		"issuanceDate": "$(date -u +'%FT%TZ')",
		"credentialSubject": {
			"id": "uuid:$(uuidgen)"
		}
	}
	EOF
}
```
### Run generation function on loop

* This will generate a file named `creds` with a stringified verifiable credential on each line, with as many lines as the value of `count`.

```bash
creds_file=creds
printf 'Writing to file "%s"\n' "$creds_file"
touch "$creds_file"

i=1
count=100
while [ $i -le $count ]; do
	printf '\rGenerating credentials... %d/%d' $i $count >&2
	generate_credential
	: $((i = i+1))
done > "$creds_file"
printf '\nDone\n'
```


## Batch Verification Script Setup

:::note
In this script, a verification method is derived from a local key and manually passed with the -v parameter. This is not the default behavior of DIDKit's verification function, but it greatly accelerates the verification of a large batch of VCs being testing against the known key material and verification method of a known issuer.

Were one to remove the `key.jwk` check, the generation of a verification method, and the passing of that method to the verification function, a verification method would be extracted for each VC verified, from the DID Document of the issuer, which would be resolved each time as specified in the VC being verified. This is the default behavior of DIDKit.
:::

```bash
#!/bin/sh

# Exit if any command in this script fails.
set -e

if [ ! -e issuer_key.jwk ]; then
	echo 'Missing keypair.' >&2
	exit 1
fi

issuer_vm=$(didkit key-to-verification-method -k issuer_key.jwk)
printf 'Issuer verification method: %s\n' "$issuer_vm"
```

### Define verification function

```bash
verify_credential() {
	if ! out=$(didkit vc-verify-credential \
		-v "$issuer_vm" \
		-p assertionMethod)
	then
		printf "verify failed: %s" "$out" >&2
		return 1
	fi
}
```
### Run verification function on loop
Here we loop through the file created above, verifying the credential contained on each line.

```bash
creds_file=creds
printf 'Reading from file "%s"\n' "$creds_file"

i=1
jq -c . "$creds_file" | while read line; do
	printf '\rVerifying credentials... %d' $i
	printf "%s" "$line" | verify_credential 
	: $((i = i+1))
done
printf '\nDone\n'


```


## Appendix: whole script 

Also available on Github as
* [/cli/tests/example2-batch-generation.sh](https://github.com/spruceid/didkit/cli/tests/example2-batch-generation.sh)
* [/cli/tests/example2-batch-verification.sh](https://github.com/spruceid/didkit/cli/tests/example2-batch-verification.sh)

```bash
#!/bin/sh

# Exit if any command in this script fails.
set -e

if [ -e issuer_key.jwk ]; then
	echo 'Using existing keypair.'
else
	didkit generate-ed25519-key > issuer_key.jwk
	echo 'Generated keypair.'
fi
issuer=$(didkit key-to-did-key -k issuer_key.jwk)
printf 'Issuer DID: %s\n' "$issuer"
issuer_vm=$(didkit key-to-verification-method -k issuer_key.jwk)
printf 'Issuer verification method: %s\n' "$issuer_vm"

# Generate a new dummy credential
generate_credential() {
	didkit vc-issue-credential \
		-k issuer_key.jwk \
		-v "$issuer_vm" \
		-p assertionMethod <<-EOF
	{
		"@context": "https://www.w3.org/2018/credentials/v1",
		"id": "uuid:$(uuidgen)",
		"type": ["VerifiableCredential"],
		"issuer": "$issuer",
		"issuanceDate": "$(date -u +'%FT%TZ')",
		"credentialSubject": {
			"id": "uuid:$(uuidgen)"
		}
	}
	EOF
}

# Generate a bunch of verifiable credentials
creds_file=creds
printf 'Writing to file "%s"\n' "$creds_file"
touch "$creds_file"

i=1
count=100
while [ $i -le $count ]; do
	printf '\rGenerating credentials... %d/%d' $i $count >&2
	generate_credential
	: $((i = i+1))
done > "$creds_file"
printf '\nDone\n'
```

```bash
#!/bin/sh

# Exit if any command in this script fails.
set -e

if [ ! -e issuer_key.jwk ]; then
	echo 'Missing keypair.' >&2
	exit 1
fi

issuer_vm=$(didkit key-to-verification-method -k issuer_key.jwk)
printf 'Issuer verification method: %s\n' "$issuer_vm"

verify_credential() {
	if ! out=$(didkit vc-verify-credential \
		-v "$issuer_vm" \
		-p assertionMethod)
	then
		printf "verify failed: %s" "$out" >&2
		return 1
	fi
}

creds_file=creds
printf 'Reading from file "%s"\n' "$creds_file"

i=1
jq -c . "$creds_file" | while read line; do
	printf '\rVerifying credentials... %d' $i
	printf "%s" "$line" | verify_credential 
	: $((i = i+1))
done
printf '\nDone\n'


```