// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package os

import (
	"fmt"
	"regexp"
)

var (
	// hostIDRe matches: {mount}/hosts/{name}
	hostIDRe = regexp.MustCompile(`^([^/]+)/hosts/([^/]+)$`)
	// accountIDRe matches: {mount}/hosts/{host}/accounts/{name}
	accountIDRe = regexp.MustCompile(`^([^/]+)/hosts/([^/]+)/accounts/([^/]+)$`)
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
