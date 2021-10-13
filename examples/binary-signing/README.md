# Binary signing example

Use Verifiable Credentials and DIDKit to sign and verify binary files.

## Credential Format

The [credential subject][] represents a binary file, and is expected to have a `digest` (`https://w3id.org/security#digest`) property, and a `contentSize` (https://schema.org/contentSize) property.  The `contentSize` property encodes the file size in bytes, as a string with "B" suffix. The `digest` property contains an object of type `Digest` (https://w3id.org/security#Digest), which has properties `digestAlgorithm` (https://w3id.org/security#digestAlgorithm) and `digestValue` (https://w3id.org/security#digestValue). The currently supported digest algorithm is SHA-256 (`sha256`; http://www.w3.org/2001/04/xmlenc#sha256). The digest value is encoded as a lowercase hexadecimal string. The credential subject may also encode the file's content-type in the `encodingFormat` (https://schema.org/encodingFormat) property, for informative purposes.

See [hello-vc.jsonld](./hello-vc.jsonld) in this directory for an example verifiable credential over file [hello.txt](./hello.txt).

## Program

The example program in this directory is a shell script using DIDKit to issue or verify a binary signing verifiable credential. The script uses AWK to extract and verify the [claims][] encoded in the verifiable credential.

### Sign

To issue a verifiable credential to sign over a file, run the `sign` subcommand of the `index.sh` program in this directory, passing the filename to sign over, your DID to issue the credential, verification method id for signing, and JWK filename. 

#### SSH Agent

By default, signing uses DIDKit's ssh-agent functionality. The JWK file passed as an argument should contain the public key for the verification method. `ssh-agent` must be running in the current shell. To start a new shell with ssh-agent, run `ssh-agent bash`. Then run `ssh-add` to unlock your SSH public keys and add them to ssh-agent - or use `ssh-add` to unlock specific keys. For more info, see the manual pges for `ssh-agent(1)` and `ssh-add(1)`. To not use `ssh-agent`, set environmental variable `USE_SSH_AGENT=no` before running the sign command, and pass your private key for signing as the JWK argument.

#### Key selection

If you are using signing with ssh-agent, convert your SSH public key to a JWK public key:
```
didkit ssh-pk-to-jwk "$(cat ~/.ssh/id_ed25519.pub)" > sshpk.jwk
jwk=sshpk.jwk
```
If you are signing without ssh-agent and want to use a new keypair, generate one with DIDKit:
```
didkit generate-ed25519-key > edsk.jwk
jwk=edsk.jwk
export USE_SSH_AGENT=no
```

Otherwise, if you have a JWK already, find it:
```
jwk=key.jwk
```

Construct the DID and verification method id. If issuing using `did:key`:
```
did=$(didkit key-to-did key -k $jwk)
vm=$(didkit key-to-verification-method key -k $jwk)
```

If using `did:web` or `did:webkey`, you can use DIDKit to resolve the DID and manually find the verification method ID to use. It should match the JWK that you pass to the sign command below.
```
did='did:web:example.org'
didkit did-resolve "$did"
...
vm='did:web:example.org#key1'
```

Perform signing, saving the resulting verifiable credential to a file:
```
./index.sh sign hello.txt "$did" "$vm" "$jwk" | jq > hello-vc.jsonld
```

#### Verify

Run the verify subcommand, passing the file and the verifiable credential. The command should return with a zero exit status on successful verification.
```
./index.sh verify hello.txt hello-vc.jsonld
```

[credential subject]: https://www.w3.org/TR/vc-data-model/#credential-subject
[claims]: https://www.w3.org/TR/vc-data-model/#claims
