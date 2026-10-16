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

// parseTransitKeyID parses a Transit key import ID in either canonical format ({mount}/keys/{name})
// or shorthand format ({mount}/{name}).
func parseTransitKeyID(id string) (string, string, error) {
	trimmed := strings.Trim(id, "/")
	if matches := keyIDWithKeysRegex.FindStringSubmatch(trimmed); len(matches) == 3 {
		return strings.Trim(matches[1], "/"), strings.Trim(matches[2], "/"), nil
	}
	// If the original ID ended with "/keys/" or was "keys/", it's an incomplete canonical path missing the key name.
	if strings.HasSuffix(strings.TrimRight(id, "/"), "/keys") && strings.HasSuffix(id, "/") {
		return "", "", fmt.Errorf("invalid transit key import ID %q: missing key name after '/keys/'", id)
	}
	if matches := keyIDSimpleRegex.FindStringSubmatch(trimmed); len(matches) == 3 {
		return strings.Trim(matches[1], "/"), strings.Trim(matches[2], "/"), nil
	}
	return "", "", fmt.Errorf("invalid transit key import ID %q: expected 'mount/keys/name' or 'mount/name'", id)
}

// parseTransitKeyVersionID parses a Transit key version import ID in either canonical format
// ({mount}/keys/{name}/version/{ver}) or shorthand format ({mount}/{name}/{ver}).
// The canonical regex must be evaluated first to avoid greedy matching on shorthand format.
func parseTransitKeyVersionID(id string) (string, string, int64, error) {
	id = strings.Trim(id, "/")
	if matches := keyVersionIDWithKeysRegex.FindStringSubmatch(id); len(matches) == 4 {
		v, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			return "", "", 0, fmt.Errorf("invalid version number in ID %q: %w", id, err)
		}
		return strings.Trim(matches[1], "/"), strings.Trim(matches[2], "/"), v, nil
	}
	if matches := keyVersionIDSimpleRegex.FindStringSubmatch(id); len(matches) == 4 {
		v, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			return "", "", 0, fmt.Errorf("invalid version number in ID %q: %w", id, err)
		}
		return strings.Trim(matches[1], "/"), strings.Trim(matches[2], "/"), v, nil
	}
	return "", "", 0, fmt.Errorf("invalid transit key version import ID %q: expected 'mount/keys/name/version/<ver>' or 'mount/name/<ver>'", id)
}
