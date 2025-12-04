// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"encoding/json"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/helper"
)

// ReadPolicyIdentifierBlocks converts the `policy_identifiers` list and `policy_identifier` blocks
// into a list of strings (the OIDs) or the JSON serialization of the `policy_identifier` blocks,
// respectively.
func ReadPolicyIdentifierBlocks(policyIdentifierBlocks *schema.Set) string {
	if policyIdentifierBlocks == nil || policyIdentifierBlocks.Len() == 0 {
		return ""
	}

	var newPolicyIdentifiers []map[string]interface{}

	// If the `policy_identifier` blocks are present, send them as JSON, which is only supported by Vault 1.11+.
	newPolicyIdentifiers = make([]map[string]interface{}, 0, policyIdentifierBlocks.Len())
	for _, iPolicyIdentifier := range policyIdentifierBlocks.List() {
		policyIdentifier := iPolicyIdentifier.(map[string]interface{})
		newPolicyIdentifiers = append(newPolicyIdentifiers, policyIdentifier)
	}
	// we know these maps are safe to marshal
	policyIdentifiersJson, _ := json.Marshal(newPolicyIdentifiers)
	return string(policyIdentifiersJson)
}

// MakePkiPolicyIdentifiersListOrSet converts the Vault "policy_identifiers" response
// into either a list of OIDs, i.e., ["1.2.3","4.5.6"], or a set to represent
// `policy_identifier` blocks. We return either of these so that round-tripping is stable,
// and to preserve backwards compatibility with previous versions of Vault.
func MakePkiPolicyIdentifiersListOrSet(rawPolicyIdentifiers []interface{}) ([]string, *schema.Set, error) {
	policyIdentifiers := make([]string, 0, len(rawPolicyIdentifiers))
	newPolicyIdentifiers := schema.NewSet(pkiPolicyIdentifierHash, []interface{}{})
	for _, iIdentifier := range rawPolicyIdentifiers {
		policyString := iIdentifier.(string)
		if strings.HasPrefix(policyString, "{") && strings.HasSuffix(policyString, "}") {
			var policyMap = map[string]string{}
			err := json.Unmarshal([]byte(policyString), &policyMap)
			if err != nil {
				return nil, nil, err
			}
			newPolicyIdentifiers.Add(policyMap)
		} else {
			// older Vault version with oid-only response
			policyIdentifiers = append(policyIdentifiers, policyString)
		}
	}

	if newPolicyIdentifiers.Len() == 0 {
		return policyIdentifiers, nil, nil
	}
	return nil, newPolicyIdentifiers, nil
}

func pkiPolicyIdentifierHash(v interface{}) int {
	m := v.(map[string]string)
	s, _ := json.Marshal(m) // won't fail since we know the argument is a map[string]string
	return helper.HashCodeString(string(s))
}
