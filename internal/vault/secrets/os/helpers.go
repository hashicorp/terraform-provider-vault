// Copyright (c) HashiCorp, Inc.
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

// makeHostID creates ID for host resource
func makeHostID(mount, name string) string {
	return fmt.Sprintf("%s/hosts/%s", mount, name)
}

// makeAccountID creates ID for account resource
func makeAccountID(mount, host, name string) string {
	return fmt.Sprintf("%s/hosts/%s/accounts/%s", mount, host, name)
}

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
