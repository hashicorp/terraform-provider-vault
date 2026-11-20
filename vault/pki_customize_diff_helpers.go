// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiValidateKeyTypeField(d *schema.ResourceDiff, meta interface{}) error {
	if provider.IsAPISupported(meta, provider.VaultVersion220) {
		return nil
	}
	keyType, ok := d.GetOk(consts.FieldKeyType)
	if !ok {
		return nil
	}
	keyTypeStr := keyType.(string)
	if strings.ToLower(keyTypeStr) == "ml-dsa" {
		return fmt.Errorf("ml-dsa is only supported on Vault %s or later", consts.VaultVersion220)
	}
	return nil
}

func pkiValidateFormatField(d *schema.ResourceDiff, meta interface{}) error {
	if provider.IsAPISupported(meta, provider.VaultVersion210) {
		return nil
	}

	format, ok := d.GetOk(consts.FieldFormat)
	if !ok {
		return nil
	}

	formatStr := format.(string)
	switch formatStr {
	case "pkcs12_bundle", "jks_bundle":
		return fmt.Errorf("%q format is only supported on Vault %s or later", formatStr, consts.VaultVersion210)
	default:
		return nil
	}
}

// pkiCertPlanAutoRenewal proposes automatic renewal during planning (if enabled)
// because the Create and Read functions will both set renew_pending if
// the current time is after the min_seconds_remaining timestamp.
func pkiCertPlanAutoRenewal(d *schema.ResourceDiff) error {
	if d.Id() == "" || !d.Get(consts.FieldAutoRenew).(bool) {
		return nil
	}
	if d.Get(consts.FieldRenewPending).(bool) {
		log.Printf("[DEBUG] certificate %q is due for renewal", d.Id())
		if err := d.SetNewComputed(consts.FieldCertificate); err != nil {
			return err
		}

		if err := d.ForceNew(consts.FieldCertificate); err != nil {
			return err
		}

		// Renewing the certificate will reset the value of renew_pending
		d.SetNewComputed(consts.FieldRenewPending)
		if err := d.ForceNew(consts.FieldRenewPending); err != nil {
			return err
		}

		return nil
	}

	log.Printf("[DEBUG] certificate %q is not due for renewal", d.Id())
	return nil
}

func pkiWarnManagedKeyWithMismatchedType(intermediateType, managedKeyID, managedKeyName, keyRef string) diag.Diagnostics {
	var diags diag.Diagnostics
	// Conflict between non-KMS keys and managed_key fields
	if intermediateType != keyTypeKMS {
		if managedKeyID != "" {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "managed_key_id is ignored when type is not 'kms'",
				Detail:   "managed_key_id is ignored when type is not 'kms'; Vault will continue with the behavior of the type specified.",
			})
		}
		if managedKeyName != "" {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "managed_key_name is ignored when type is not 'kms'",
				Detail:   "managed_key_name is ignored when type is not 'kms'; Vault will continue with the behavior of the type specified.",
			})
		}
	}
	// Conflict between key_ref and non-existing keys
	if intermediateType != consts.FieldExisting {
		if keyRef != "" {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "key_ref is ignored when type is not 'existing'",
				Detail:   "key_ref is ignored when type is not 'existing'; Vault will continue with the behavior of the type specified.",
			})
		}
	}

	return diags
}
