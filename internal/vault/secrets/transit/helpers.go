// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	// keyIDWithKeysRegex matches canonical import: {mount}/keys/{name} (e.g. transit/keys/my-key)
	keyIDWithKeysRegex = regexp.MustCompile(`^(.+)/keys/([^/]+)$`)

	// keyIDSimpleRegex matches shorthand import: {mount}/{name} (e.g. transit/my-key)
	keyIDSimpleRegex = regexp.MustCompile(`^(.+)/([^/]+)$`)

	// keyVersionIDWithKeysRegex matches canonical version import: {mount}/keys/{name}/version/{ver} (e.g. transit/keys/my-key/version/2)
	keyVersionIDWithKeysRegex = regexp.MustCompile(`^(.+)/keys/([^/]+)/version/(\d+)$`)

	// keyVersionIDSimpleRegex matches shorthand version import: {mount}/{name}/{ver} (e.g. transit/my-key/2)
	keyVersionIDSimpleRegex = regexp.MustCompile(`^(.+)/([^/]+)/(\d+)$`)
)

type parsedKeyID struct {
	Mount string
	Name  string
}

type parsedKeyVersionID struct {
	Mount   string
	Name    string
	Version int64
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
//   - the resource type (a Vault transit key import or key version import resource)
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

// parseTransitKeyVersionID parses the ID used when importing a vault_transit_secret_backend_key_import_version
// resource into Terraform state.
//
//	terraform import vault_transit_secret_backend_key_import_version.example transit/keys/my-key/version/2
//	terraform import vault_transit_secret_backend_key_import_version.example transit/my-key/2
func parseTransitKeyVersionID(id string) (parsedKeyVersionID, error) {
	id = strings.Trim(id, "/")
	if matches := keyVersionIDWithKeysRegex.FindStringSubmatch(id); len(matches) == 4 {
		v, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			return parsedKeyVersionID{}, fmt.Errorf("invalid version number in ID %q: %w", id, err)
		}
		return parsedKeyVersionID{Mount: strings.Trim(matches[1], "/"), Name: strings.Trim(matches[2], "/"), Version: v}, nil
	}
	if matches := keyVersionIDSimpleRegex.FindStringSubmatch(id); len(matches) == 4 {
		v, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			return parsedKeyVersionID{}, fmt.Errorf("invalid version number in ID %q: %w", id, err)
		}
		return parsedKeyVersionID{Mount: strings.Trim(matches[1], "/"), Name: strings.Trim(matches[2], "/"), Version: v}, nil
	}
	return parsedKeyVersionID{}, fmt.Errorf("invalid transit key version import ID %q: expected 'mount/keys/name/version/<ver>' or 'mount/name/<ver>'", id)
}
