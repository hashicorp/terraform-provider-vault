package vault

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/hashicorp/terraform-provider-vault/helper"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// readPolicyIdentifiers converts the `policy_identifiers` list and `policy_identifier` blocks
// into a list of strings (the OIDs) or the JSON serialization of the `policy_identifier` blocks,
// respectively.
func readPolicyIdentifiers(d *schema.ResourceData) interface{} {
	policyIdentifiersList := d.Get("policy_identifiers").([]interface{})
	policyIdentifierBlocks := d.Get("policy_identifier").(*schema.Set)
	policyIdentifiers := make([]string, 0, len(policyIdentifiersList))
	var newPolicyIdentifiers []map[string]interface{}

	// If the `policy_identifier` blocks are present, send them as JSON, which is only supported by Vault 1.11+.
	if policyIdentifierBlocks != nil && policyIdentifierBlocks.Len() > 0 {
		newPolicyIdentifiers = make([]map[string]interface{}, 0, policyIdentifierBlocks.Len()+len(policyIdentifiers))
		for _, iPolicyIdentifier := range policyIdentifierBlocks.List() {
			policyIdentifier := iPolicyIdentifier.(map[string]interface{})
			newPolicyIdentifiers = append(newPolicyIdentifiers, policyIdentifier)
		}

		if policyIdentifiersList != nil && len(policyIdentifiersList) > 0 {
			log.Printf("[WARN] vault_pki_secret_backend_role policy_identifier and policy_identifiers should not both be used; ignoring legacy policy_identifiers")
		}

		// we know these maps are safe to marshal
		policyIdentifiersJson, _ := json.Marshal(newPolicyIdentifiers)
		return string(policyIdentifiersJson)
	} else if policyIdentifiersList != nil && len(policyIdentifiersList) > 0 {
		for _, iIdentifier := range policyIdentifiersList {
			policyIdentifiers = append(policyIdentifiers, iIdentifier.(string))
		}
		return policyIdentifiers
	} else {
		return nil
	}
}

// makePkiPolicyIdentifiersListOrSet converts the Vault "policy_identifiers" response
// into either a list of OIDs, i.e., ["1.2.3","4.5.6"], or a set to represent
// `policy_identifier` blocks. We return either of these so that round-tripping is stable,
// and to preserve backwards compatibility with previous versions of Vault.
func makePkiPolicyIdentifiersListOrSet(rawPolicyIdentifiers []interface{}) ([]string, *schema.Set, error) {
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
