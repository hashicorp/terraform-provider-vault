// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/vault/api"
	"strings"
)

func pkiSecretBackendConfigCMPV2DataSource() *schema.Resource {
	return &schema.Resource{
		Description: "Reads Vault PKI CMPv2 configuration",
		ReadContext: provider.ReadContextWrapper(readPKISecretBackendConfigCMPV2),
		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path where PKI engine is mounted",
			},
			consts.FieldEnabled: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Specifies whether CMPv2 is enabled",
			},
			consts.FieldDefaultPathPolicy: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Can be sign-verbatim or a role given by role:<role_name>",
			},
			consts.FieldAuthenticators: {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Lists the mount accessors CMPv2 should delegate authentication requests towards",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cert": {
							Type:        schema.TypeMap,
							Optional:    true,
							Description: "The accessor and cert_role properties for cert auth backends",
						},
					},
				},
			},
			consts.FieldEnableSentinelParsing: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "If set, parse out fields from the provided CSR making them available for Sentinel policies",
			},
			consts.FieldAuditFields: {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Fields parsed from the CSR that appear in the audit and can be used by sentinel policies",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldDisabledValidations: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "A comma-separated list of validations not to perform on CMPv2 messages.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldLastUpdated: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "A read-only timestamp representing the last time the configuration was updated",
			},
		},
	}
}

func readPKISecretBackendConfigCMPV2(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := verifyPkiEstFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed getting client: %w", err))
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := pkiSecretBackendConfigCMPV2Path(backend)

	if err := readCMPV2Config(ctx, d, client, path); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func readCMPV2Config(ctx context.Context, d *schema.ResourceData, client *api.Client, path string) error {
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
		consts.FieldEnableSentinelParsing,
		consts.FieldAuditFields,
		consts.FieldDisabledValidations,
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

// verifyPkiCMPV2FeatureSupported verifies that we are talking to a Vault enterprise edition
// and its version 1.18.0 or higher, returns nil if the above is met, otherwise an error
func verifyPkiCMPV2FeatureSupported(meta interface{}) error {
	currentVersion := meta.(*provider.ProviderMeta).GetVaultVersion()

	minVersion := provider.VaultVersion118
	if !provider.IsAPISupported(meta, minVersion) {
		return fmt.Errorf("feature not enabled on current Vault version. min version required=%s; "+
			"current vault version=%s", minVersion, currentVersion)
	}

	if !provider.IsEnterpriseSupported(meta) {
		return errors.New("feature requires Vault Enterprise")
	}
	return nil
}

func pkiSecretBackendConfigCMPV2Path(backend string) string {
	return strings.Trim(backend, "/") + "/config/cmp"
}
