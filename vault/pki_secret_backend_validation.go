// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

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
		return fmt.Errorf("%q format is only supported on Vault %s or newer", formatStr, consts.VaultVersion210)
	default:
		return nil
	}
}
