#!/bin/sh
set -e
cd "$(dirname "$0")"

# Create and use temp directory if does not already exist
dir=did-ion-test
if test -d "$dir"
then
	printf 'Directory already exists: %s\n' "$dir" >&2
	exit 1
fi
mkdir "$dir"
cd "$dir"

# Generate initial update keypair and initial recovery keypair
didkit key generate secp256k1 > 1-u.jwk
didkit key generate secp256k1 > 1-r.jwk
# Construct Create operation with initial public keys
didkit did-create ion -r 1-r.jwk -u 1-u.jwk | tee 1-create.json
# Get long-form and short-form DID from Create operation
longdid=$(didkit did-from-tx < 1-create.json)
shortdid=$(echo -n "$longdid" | sed 's/:[^:]*$//')
didsuffix=$(echo -n "$shortdid" | sed 's/.*://')
echo "Sidetree DID Suffix: $didsuffix"
echo "DID (long-form/unpublished): $longdid"
echo "DID (short-form/canonical): $shortdid"

# Now that the DID suffix is set, rename the directory to it.
cd ..
mv "$dir" "$didsuffix"
cd "$didsuffix"

# Submit Create operation
export DID_ION_API_URL=http://localhost:3000/
read -p "Press enter to submit Create operation. " _
didkit did-submit-tx < 1-create.json

# Generate verification key to be added to DID document
didkit key generate secp256k1 > 2-v.jwk
# Construct DID URL for new verification method
vm="$shortdid#key-1"

# Generate new update key keypair
didkit key generate secp256k1 > 2-u.jwk
# Construct Update operation to add verification key to DID document
didkit did-update -U 1-u.jwk -u 2-u.jwk \
	set-verification-method "$vm" -k 2-v.jwk \
	--authentication --assertionMethod -t JsonWebKey2020 \
	| tee 2-update.json
# Submit Update operation
read -p 'Press enter to submit Update operation. ' _
if ! didkit did-submit-tx < 2-update.json
then
	read -p 'Press enter to retry submit operation. ' _
	didkit did-submit-tx < 2-update.json
fi

