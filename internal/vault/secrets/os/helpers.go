// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package os

import (
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

var (
	// hostIDRe matches: {mount}/hosts/{name}
	hostIDRe = regexp.MustCompile(`^(` + consts.GenericNameRegex + `)/hosts/(` + consts.GenericNameRegex + `)$`)
	// accountIDRe matches: {mount}/hosts/{host}/accounts/{name}
	accountIDRe = regexp.MustCompile(`^(` + consts.GenericNameRegex + `)/hosts/(` + consts.GenericNameRegex + `)/accounts/(` + consts.GenericNameRegex + `)$`)
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
