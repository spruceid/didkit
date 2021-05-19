#!/bin/sh
# Example/test of using DIDKit with ssh-agent for signing
cargo build -p didkit-cli
cd "$(dirname "$0")"
export PATH="$PWD/../../target/debug:$PATH"

eval "$(ssh-agent -s)"
for alg in ed25519 ecdsa; do
	ssh-keygen -q -N '' -t $alg -f id_$alg
	cut -f1 -d' ' id_$alg.pub
	didkit ssh-pk-to-jwk "$(cat id_$alg.pub)" > pk_$alg
	ssh-add -q id_$alg
	did=$(didkit key-to-did key -k pk_$alg)
	vm=$(didkit key-to-verification-method key -k pk_$alg)
	didkit did-auth -h "$did" -v "$vm" -k pk_$alg --ssh-agent > didauth.jsonld
	didkit vc-verify-presentation < didauth.jsonld; echo
	rm id_$alg id_$alg.pub pk_$alg
done
ssh-agent -k
# rsa is not tested because there is no generative DID method for it
