#!/bin/sh
set -e
prog=${0##*/}
dir=${0%/*}
export PATH="$dir/../../target/debug:$PATH"

err() {
	code=$1; shift
	printf "$@"
	exit $code
}

sign() {
	file=${1?file}
	did=${2?did}
	vm=${3?verification method}
	pk=${4?public_key.jwk}
	content_type=$(file -b --mime-type "$file")
	size=$(wc -c < "$file")
	sha256sum=$(shasum -a 256 "$file" | cut -f1 -d ' ')
	date=$(date -u +%FT%TZ)
	case "$USE_SSH_AGENT" in
		''|[yY]*) ssh_agent_arg=-S;;
		[nN]*) ssh_agent_arg=;;
		*) err 1 "%s: Unknown option for \$USE_SSH_AGENT: '%s'\n" "$prog" "$USE_SSH_AGENT";; 
	esac
	didkit vc-issue-credential \
		-p assertionMethod \
		-k "$pk" -v "$vm" \
		$ssh_agent_arg \
<<EOF
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    {
      "@version": 1.1,
      "@protected": true,
      "contentSize": "https://schema.org/contentSize",
      "encodingFormat": "https://schema.org/encodingFormat",
      "digest": "https://w3id.org/security#digest",
      "Digest": "https://w3id.org/security#Digest",
      "digestAlgorithm": {
        "@id": "https://w3id.org/security#digestAlgorithm",
        "@type": "@vocab",
        "@context": {
          "@version": 1.1,
          "@protected": true,
          "sha256": "http://www.w3.org/2001/04/xmlenc#sha256"
        }
      },
      "digestValue": "https://w3id.org/security#digestValue"
    }
  ],
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "$did",
  "issuanceDate": "$date",
  "credentialSubject": {
    "contentSize": "${size}B",
    "encodingFormat": "$content_type",
    "digest": {
      "@type": "Digest",
      "digestAlgorithm": "sha256",
      "digestValue": "$sha256sum"
    }
  }
}
EOF
}

verify() {
	file=${1?file}
	vc=${2?verifiable credential}
	didkit vc-verify-credential -p assertionMethod < "$vc"
	echo
	didkit to-rdf-urdna2015 < "$vc" | awk \
	  -f $dir/rdf.awk \
	  -f $dir/verify.awk \
	  -v file=$file
}

usage() {
	cat <<-EOF
	Usage: $prog <command>...
	Commands:
	  sign <file> <did> <vm> <pk_jwk> > <vc_file>
	  verify <file> <vc_file>
	EOF
}

if [ "$#" -eq 0 ]; then
	usage
	exit
fi
cmd=$1; shift
case "$cmd" in
	sign) sign "$@";;
	verify) verify "$@";;
	*) err 1 "%s: Unknown command '%s'\n" "$prog" "$cmd";;
esac
