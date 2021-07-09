# rdf.awk - Parse RDF N-Quads in AWK
# Copyright 2021 Spruce Systems, Inc.
# Apache License, Version 2.0
#
# Resources:
# - https://www.w3.org/TR/n-quads/#sec-grammar
# - https://pubs.opengroup.org/onlinepubs/9699919799/utilities/awk.html

# RDF statements are parsed from input records into four global arrays:
#   SUBJECTS, PREDICATES, OBJECTS, GRAPH_LABELS

$NF != "." {
	printf "%d: Missing \".\" at end\n", NR > "/dev/stderr"
	exit 1
}

{
	subject = $1
	predicate = $2
	if (match($0, /".*"/)) {
		# Parse object term which may contain spaces,
		# so that space can still be used as field separator.
		object = substr($0, RSTART, RLENGTH)
		sub(/".*"/, "STRING")
	} else {
		object = $3
	}
	if (NF == 5) {
		graph_label = $4
	} else if (NF == 4) {
		graph_label = ""
	} else {
		printf "%d: Unexpected number of fields: %d\n", NR, NF > "/dev/stderr"
		exit 1
	}
	# Store statement terms across four global variables.
	SUBJECTS[NR] = subject
	PREDICATES[NR] = predicate
	OBJECTS[NR] = object
	GRAPH_LABELS[NR] = graph_label
}

# Select RDF statements matching the given subject, predicate, object, and/or
# graph label. Put results in the passed results array, with index starting at
# 1 and value equal to the row number of the matching statement. Return the
# number of matched statements.
function select_statements(subject, predicate, object, graph_label, results) {
	num_results = 0
	for (i = 0; i <= NR; i++) {
		if        ((    subject == "*" || subject == SUBJECTS[i]) \
			&& (  predicate == "*" || predicate == PREDICATES[i]) \
			&& (     object == "*" || object == OBJECTS[i]) \
			&& (graph_label == "*" || graph_label == GRAPH_LABELS[i]) \
		) {
			results[++num_results] = i
		}
	}
	return num_results
}

# Select an RDF statement matching the given subject, predicate, object, and/or
# graph label. Return the row number of the matched statement. Exit with an
# error if no statement matched or if more than one statement matched.
function select_statement(subject, predicate, object, graph_label) {
	n = select_statements(subject, predicate, object, graph_label, results)
	if (n == 0) {
		printf "Found no matching statement for (%s, %s, %s, %s)\n", subject, predicate, object, graph_label > "/dev/stderr"
		exit 1
	}
	if (n > 1) {
		printf "Found multiple statements for (%s, %s, %s, %s)\n", subject, predicate, object, graph_label > "/dev/stderr"
		exit 1
	}
	return results[1]
}
