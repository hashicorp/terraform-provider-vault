// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package os

import (
	"fmt"
	"regexp"
)

var (
	// namePattern matches valid Vault names using the same pattern as framework.GenericNameRegex
	// Pattern: \w(?:(?:[\w-.]+)?\w)?
	// - Must start with a word character (letter, digit, or underscore)
	// - Optionally can have middle characters (word chars, hyphens, dots) followed by ending word char
	// - Single character names are valid (the entire optional group can be omitted)
	// - No leading/trailing hyphens or dots allowed
	// Uses non-capturing groups (?:...) to avoid extra capture groups in regex matches
	namePattern = `\w(?:(?:[\w-.]+)?\w)?`

	// hostIDRe matches: {mount}/hosts/{name}
	hostIDRe = regexp.MustCompile(`^(` + namePattern + `)/hosts/(` + namePattern + `)$`)
	// accountIDRe matches: {mount}/hosts/{host}/accounts/{name}
	accountIDRe = regexp.MustCompile(`^(` + namePattern + `)/hosts/(` + namePattern + `)/accounts/(` + namePattern + `)$`)
)

// parseHostID parses host resource ID
func parseHostID(id string) (mount, name string, err error) {
	matches := hostIDRe.FindStringSubmatch(id)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid host ID format: %s", id)
	}
	return matches[1], matches[2], nil
}

// parseAccountID parses account resource ID
func parseAccountID(id string) (mount, host, name string, err error) {
	matches := accountIDRe.FindStringSubmatch(id)
	if len(matches) != 4 {
		return "", "", "", fmt.Errorf("invalid account ID format: %s", id)
	}
	return matches[1], matches[2], matches[3], nil
}

// Made with Bob
