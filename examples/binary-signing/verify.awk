# Depends on: rdf.awk

END {
	vc_id = SUBJECTS[select_statement("*", "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>", "<https://www.w3.org/2018/credentials#VerifiableCredential>", "")]
	sub_id = OBJECTS[select_statement(vc_id, "<https://www.w3.org/2018/credentials#credentialSubject>", "*", "")]
	size_term = OBJECTS[select_statement(sub_id, "<https://schema.org/contentSize>", "*", "")]
	if (!match(size_term, /^"[0-9]+B"$/)) {
		printf "Unable to match size: %s\n", size_term > "/dev/stderr"
		exit 1
	}
	size_bytes = substr(size_term, 2, RLENGTH-3)
	#format_term = OBJECTS[select_statement(sub_id, "<https://schema.org/encodingFormat>", "*", "")]
	digest_id = OBJECTS[select_statement(sub_id, "<https://w3id.org/security#digest>", "*", "")]
	select_statement(digest_id, "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>", "<https://w3id.org/security#Digest>", "")
	select_statement(digest_id, "<https://w3id.org/security#digestAlgorithm>", "<http://www.w3.org/2001/04/xmlenc#sha256>", "")
	digest_value_term = OBJECTS[select_statement(digest_id, "<https://w3id.org/security#digestValue>", "*", "")]
	if (!match(digest_value_term, /^"[0-9a-f]{64}"$/)) {
		printf "Unable to match digest: %s\n", digest_value_term > "/dev/stderr"
		exit 1
	}
	digest_hex = substr(digest_value_term, 2, 64)
	if (("wc -c " file) | getline < 0) {
		print "Unable to calculate file size" > "/dev/stderr"
		exit 1
	}
	if ($1 != size_bytes) {
		printf "File size mismatch. Credential said: %d, but we counted %d.\n", size_bytes, $1 > "/dev/stderr"
		exit 1
	}
	if (("shasum -a 256 " file) | getline < 0) {
		print "Unable to calculate file digest" > "/dev/stderr"
		exit 1
	}
	if ($1 != digest_hex) {
		printf "Digest mismatch. Credential said: %s, but we calculated %s.\n", digest_hex, $1 > "/dev/stderr"
		exit 1
	}
	print "\033[1;32m✓\033[0m File size and digest verified." > "/dev/stderr"
}
