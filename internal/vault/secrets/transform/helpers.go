// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transform

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	typeTokenization = "tokenization"
	typeFPE          = "fpe"
)

var (
	// idWithTransformationRegex matches canonical import: {mount}/transformation/{name}
	// (e.g. transform/transformation/my-transformation)
	idWithTransformationRegex = regexp.MustCompile(`^(.+)/transformation/([^/]+)$`)

	// idSimpleRegex matches shorthand import: {mount}/{name} (e.g. transform/my-transformation)
	idSimpleRegex = regexp.MustCompile(`^(.+)/([^/]+)$`)
)

type parsedTransformationID struct {
	Mount string
	Name  string
}

// readPath is the type-agnostic endpoint used to read a transformation.
func readPath(mount, name string) string {
	return fmt.Sprintf("%s/transformation/%s", strings.Trim(mount, "/"), strings.Trim(name, "/"))
}

// typedPath is the type-specific endpoint used to update and delete a transformation.
func typedPath(mount, transformationType, name string) string {
	return fmt.Sprintf("%s/transformations/%s/%s", strings.Trim(mount, "/"), transformationType, strings.Trim(name, "/"))
}

func importPath(mount, transformationType, name string) string {
	return typedPath(mount, transformationType, name) + "/import"
}

func importVersionPath(mount, transformationType, name string) string {
	return typedPath(mount, transformationType, name) + "/import_version"
}

// tokenizationKeyPath is the endpoint that reports the key versions of a tokenization transformation.
// FPE transformations have no equivalent endpoint.
func tokenizationKeyPath(mount, name string) string {
	return fmt.Sprintf("%s/tokenization/keys/%s", strings.Trim(mount, "/"), strings.Trim(name, "/"))
}

// keyConfigPath is the endpoint used to configure the key of a tokenization transformation.
func keyConfigPath(mount, name string) string {
	return tokenizationKeyPath(mount, name) + "/config"
}

// wrappingKeyPath is the endpoint that returns the mount's public wrapping key.
func wrappingKeyPath(mount string) string {
	return fmt.Sprintf("%s/wrapping_key", strings.Trim(mount, "/"))
}

// Note: below, "import" has two separate meanings:
//   - the resource type (a Vault Transform transformation with an imported key)
//   - the Terraform import action (adding it to Terraform state)

// parseTransformationID parses the ID used when importing a
// vault_transform_transformation_{tokenization,fpe}_imported_key resource into Terraform state.
//
//	terraform import vault_transform_transformation_tokenization_imported_key.example transform/transformation/my-transformation
//	terraform import vault_transform_transformation_tokenization_imported_key.example transform/my-transformation
func parseTransformationID(id string) (parsedTransformationID, error) {
	trimmed := strings.Trim(id, "/")
	if matches := idWithTransformationRegex.FindStringSubmatch(trimmed); len(matches) == 3 {
		return parsedTransformationID{Mount: strings.Trim(matches[1], "/"), Name: strings.Trim(matches[2], "/")}, nil
	}
	// If the original ID ended with "/transformation/", it's an incomplete canonical path missing the name.
	if strings.HasSuffix(strings.TrimRight(id, "/"), "/transformation") && strings.HasSuffix(id, "/") {
		return parsedTransformationID{}, fmt.Errorf("invalid transformation import ID %q: missing name after '/transformation/'", id)
	}
	if matches := idSimpleRegex.FindStringSubmatch(trimmed); len(matches) == 3 {
		return parsedTransformationID{Mount: strings.Trim(matches[1], "/"), Name: strings.Trim(matches[2], "/")}, nil
	}
	return parsedTransformationID{}, fmt.Errorf("invalid transformation import ID %q: expected 'mount/transformation/name' or 'mount/name'", id)
}
