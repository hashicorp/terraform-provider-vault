// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/vault/api"
)

func pkiSecretBackendConfigScepSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		consts.FieldBackend: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The PKI secret backend the resource belongs to",
			ForceNew:    true,
		},
		consts.FieldEnabled: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Specifies whether SCEP is enabled",
		},
		consts.FieldDefaultPathPolicy: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The policy to be used for non-role-qualified SCEP requests; valid values are 'sign-verbatim', or "role:<role_name>" to specify a role to use as this policy.`,
		},
		consts.FieldAllowedEncryptionAlgorithms: {
			Type:        schema.TypeList,
			Optional:    true,
			Computed:    true,
			Description: "The list of allowed encryption algorithms for SCEP requests",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		consts.FieldAllowedDigestAlgorithms: {
			Type:        schema.TypeList,
			Optional:    true,
			Computed:    true,
			Description: "The list of allowed digest algorithms for SCEP requests",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		consts.FieldAuthenticators: {
			Type:        schema.TypeList,
			Optional:    true,
			Computed:    true,
			Description: "Lists the mount accessors SCEP should delegate authentication requests towards",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"cert": {
						Type:     schema.TypeMap,
						Optional: true,
					},
					"userpass": {
						Type:     schema.TypeMap,
						Optional: true,
					},
				},
			},
			MaxItems: 1,
		},
		consts.FieldLastUpdated: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "A read-only timestamp representing the last time the configuration was updated",
		},
	}
}

func pkiSecretBackendConfigScepDataSource() *schema.Resource {
	return &schema.Resource{
		Description: "Reads Vault PKI SCEP configuration",
		ReadContext: provider.ReadContextWrapper(readPKISecretBackendConfigScep),
		Schema:      pkiSecretBackendConfigScepSchema(),
	}
}

func readPKISecretBackendConfigScep(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := verifyPkiScepFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed getting client: %w", err))
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := pkiSecretBackendConfigScepPath(backend)

	if err := readScepConfig(ctx, d, client, path); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func readScepConfig(ctx context.Context, d *schema.ResourceData, client *api.Client, path string) error {
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %w", err)
	}
	if resp == nil {
		return fmt.Errorf("got nil response from Vault from path: %q", path)
	}

	d.SetId(path)

	keyComputedFields := []string{
		consts.FieldEnabled,
		consts.FieldDefaultPathPolicy,
		consts.FieldAllowedEncryptionAlgorithms,
		consts.FieldAllowedDigestAlgorithms,
		consts.FieldLastUpdated,
	}

	for _, k := range keyComputedFields {
		if fieldVal, ok := resp.Data[k]; ok {
			if err := d.Set(k, fieldVal); err != nil {
				return fmt.Errorf("failed setting field [%s] with val [%s]: %w", k, fieldVal, err)
			}
		}
	}

	if authenticators, authOk := resp.Data[consts.FieldAuthenticators]; authOk {
		if err := d.Set(consts.FieldAuthenticators, []interface{}{authenticators}); err != nil {
			return fmt.Errorf("failed setting field [%s] with val [%s]: %w", consts.FieldAuthenticators, authenticators, err)
		}
	}

	return nil
}

// verifyPkiScepFeatureSupported verifies that we are talking to a Vault enterprise edition
// and its version 1.20.0 or higher, returns nil if the above is met, otherwise an error
func verifyPkiScepFeatureSupported(meta interface{}) error {
	currentVersion := meta.(*provider.ProviderMeta).GetVaultVersion()

	minVersion := provider.VaultVersion120
	if !provider.IsAPISupported(meta, minVersion) {
		return fmt.Errorf("feature not enabled on current Vault version. min version required=%s; "+
			"current vault version=%s", minVersion, currentVersion)
	}

	if !provider.IsEnterpriseSupported(meta) {
		return errors.New("feature requires Vault Enterprise")
	}
	return nil
}

func pkiSecretBackendConfigScepPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/scep"
}
