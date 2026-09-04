// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import "github.com/hashicorp/terraform-plugin-framework/types"

// setIfNotEmpty adds key=value to the request map only when value is non-empty.
func setIfNotEmpty(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	} else {
		m[key] = types.StringNull()
	}
}

// setStringIfNotEmpty sets the target types.String only when val is non-empty,
// leaving it null otherwise. Used when reading Vault responses
// where absent fields should not overwrite configured values.
func setStringIfNotEmpty(target *types.String, val string) {
	if val != "" {
		*target = types.StringValue(val)
	} else {
		*target = types.StringNull()
	}
}
