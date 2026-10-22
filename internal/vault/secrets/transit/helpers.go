// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// keyIDWithKeysRegex matches canonical import: {mount}/keys/{name} (e.g. transit/keys/my-key)
	keyIDWithKeysRegex = regexp.MustCompile(`^(.+)/keys/([^/]+)$`)

	// keyIDSimpleRegex matches shorthand import: {mount}/{name} (e.g. transit/my-key)
	keyIDSimpleRegex = regexp.MustCompile(`^(.+)/([^/]+)$`)
)

type parsedKeyID struct {
	Mount string
	Name  string
}

func keyPath(mount, name string) string {
	return fmt.Sprintf("%s/keys/%s", strings.Trim(mount, "/"), strings.Trim(name, "/"))
}

func importPath(mount, name string) string {
	return fmt.Sprintf("%s/keys/%s/import", strings.Trim(mount, "/"), strings.Trim(name, "/"))
}

func importVersionPath(mount, name string) string {
	return fmt.Sprintf("%s/keys/%s/import_version", strings.Trim(mount, "/"), strings.Trim(name, "/"))
}

func configPath(mount, name string) string {
	return fmt.Sprintf("%s/keys/%s/config", strings.Trim(mount, "/"), strings.Trim(name, "/"))
}

func wrappingKeyPath(mount string) string {
	return fmt.Sprintf("%s/wrapping_key", strings.Trim(mount, "/"))
}

// Note: below, "import" has two separate meanings:
//   - the resource type (a Vault transit key import resource)
//   - the Terraform import action (adding it to Terraform state)

// parseTransitKeyID parses the ID used when importing a vault_transit_secret_backend_key_import
// resource into Terraform state.
//
//	terraform import vault_transit_secret_backend_key_import.example transit/keys/my-key
//	terraform import vault_transit_secret_backend_key_import.example transit/my-key
func parseTransitKeyID(id string) (parsedKeyID, error) {
	trimmed := strings.Trim(id, "/")
	if matches := keyIDWithKeysRegex.FindStringSubmatch(trimmed); len(matches) == 3 {
		return parsedKeyID{Mount: strings.Trim(matches[1], "/"), Name: strings.Trim(matches[2], "/")}, nil
	}
	// If the original ID ended with "/keys/" or was "keys/", it's an incomplete canonical path missing the key name.
	if strings.HasSuffix(strings.TrimRight(id, "/"), "/keys") && strings.HasSuffix(id, "/") {
		return parsedKeyID{}, fmt.Errorf("invalid transit key import ID %q: missing key name after '/keys/'", id)
	}
	if matches := keyIDSimpleRegex.FindStringSubmatch(trimmed); len(matches) == 3 {
		return parsedKeyID{Mount: strings.Trim(matches[1], "/"), Name: strings.Trim(matches[2], "/")}, nil
	}
	return parsedKeyID{}, fmt.Errorf("invalid transit key import ID %q: expected 'mount/keys/name' or 'mount/name'", id)
}
