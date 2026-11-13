// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

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
