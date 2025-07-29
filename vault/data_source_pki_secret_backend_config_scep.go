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

func pkiSecretBackendConfigScepDataSource() *schema.Resource {
	return &schema.Resource{
		Description: "Reads Vault PKI SCEP configuration",
		ReadContext: provider.ReadContextWrapper(readPKISecretBackendConfigScep),
		Schema:      pkiSecretBackendConfigScepDataSourceSchema,
	}
}

var pkiSecretBackendConfigScepDataSourceSchema = map[string]*schema.Schema{
	consts.FieldBackend: {
		Type:        schema.TypeString,
		Required:    true,
		ForceNew:    true,
		Description: "Path where PKI engine is mounted",
	},
	consts.FieldEnabled: {
		Type:        schema.TypeBool,
		Computed:    true,
		Description: "Specifies whether SCEP is enabled",
	},
	consts.FieldDefaultPathPolicy: {
		Type:        schema.TypeString,
		Computed:    true,
		Description: `Specifies the policy to be used for non-role-qualified SCEP requests; valid values are 'sign-verbatim', or "role:<role_name>" to specify a role to use as this policy.`,
	},
	consts.FieldAllowedEncryptionAlgorithms: {
		Type:        schema.TypeList,
		Computed:    true,
		Description: "List of allowed encryption algorithms for SCEP requests",
		Elem:        &schema.Schema{Type: schema.TypeString},
	},
	consts.FieldAllowedDigestAlgorithms: {
		Type:        schema.TypeList,
		Computed:    true,
		Description: "List of allowed digest algorithms for SCEP requests",
		Elem:        &schema.Schema{Type: schema.TypeString},
	},
	consts.FieldRestrictCAChainToIssuer: {
		Type:        schema.TypeBool,
		Computed:    true,
		Description: "If true, only return the issuer CA, otherwise the entire CA certificate chain will be returned if available from the PKI mount",
	},
	consts.FieldAuthenticators: {
		Type:        schema.TypeList,
		Computed:    true,
		Description: "Lists the mount accessors SCEP should delegate authentication requests towards",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"cert": {
					Type:        schema.TypeMap,
					Optional:    true,
					Description: "The accessor and cert_role properties for cert auth backends",
				},
				"scep": {
					Type:        schema.TypeMap,
					Optional:    true,
					Description: "The accessor property for SCEP auth backends",
				},
			},
		},
	},
	consts.FieldExternalValidation: {
		Type:        schema.TypeList,
		Computed:    true,
		Description: "Lists the 3rd party validation of SCEP requests",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"intune": {
					Type:        schema.TypeMap,
					Optional:    true,
					Description: "The credentials to enable Microsoft Intune validation of SCEP requests",
				},
			},
		},
	},
	consts.FieldLastUpdated: {
		Type:        schema.TypeString,
		Computed:    true,
		Description: "A read-only timestamp representing the last time the configuration was updated",
	},
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

	for field := range pkiSecretBackendConfigScepDataSourceSchema {
		switch field {
		case consts.FieldBackend, consts.FieldNamespace:
			continue
		case consts.FieldAuthenticators, consts.FieldExternalValidation:
			// note that it is OK to set nil values, since these fields are "computed"
			value := resp.Data[field]
			if err := d.Set(field, []any{value}); err != nil {
				return fmt.Errorf("failed setting field [%s] with val [%s]: %w", field, value, err)
			}
		default:
			if value, ok := resp.Data[field]; ok {
				if err := d.Set(field, value); err != nil {
					return fmt.Errorf("failed setting field [%s] with val [%s]: %w", field, value, err)
				}
			}
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
