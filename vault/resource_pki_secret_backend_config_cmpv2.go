// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendConfigCMPV2Resource() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages Vault PKI CMPv2 configuration",
		CreateContext: provider.MountCreateContextWrapper(pkiSecretBackendConfigCMPV2Write, provider.VaultVersion118),
		UpdateContext: pkiSecretBackendConfigCMPV2Write,
		ReadContext:   pkiSecretBackendConfigCMPV2Read,
		DeleteContext: pkiSecretBackendConfigCMPV2Delete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to",
				ForceNew:    true,
			},
			consts.FieldEnabled: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Specifies whether CMPv2 is enabled",
			},
			consts.FieldDefaultPathPolicy: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Can be sign-verbatim or a role given by role:<role_name>",
			},
			consts.FieldAuthenticators: {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "Lists the mount accessors CMPv2 should delegate authentication requests towards",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cert": {
							Type:     schema.TypeMap,
							Optional: true,
						},
					},
				},
				MaxItems: 1,
			},
			consts.FieldEnableSentinelParsing: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, parse out fields from the provided CSR making them available for Sentinel policies",
			},
			consts.FieldAuditFields: {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "Fields parsed from the CSR that appear in the audit and can be used by sentinel policies",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldLastUpdated: {
				Type:        schema.TypeString,
				Computed:    true, // read-only property
				Description: "A read-only timestamp representing the last time the configuration was updated",
			},
		},
	}
}

func pkiSecretBackendConfigCMPV2Write(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := verifyPkiCMPV2FeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := pkiSecretBackendConfigCMPV2Path(backend)

	fieldsToSet := []string{
		consts.FieldEnabled,
		consts.FieldDefaultPathPolicy,
		consts.FieldEnableSentinelParsing,
		consts.FieldAuditFields,
	}

	data := map[string]interface{}{}
	for _, field := range fieldsToSet {
		if val, ok := d.GetOk(field); ok {
			data[field] = val
		}
	}

	if authenticatorsRaw, ok := d.GetOk(consts.FieldAuthenticators); ok {
		authenticators := authenticatorsRaw.([]interface{})
		var authenticator interface{}
		if len(authenticators) > 0 {
			authenticator = authenticators[0]
		}

		data[consts.FieldAuthenticators] = authenticator
	}

	log.Printf("[DEBUG] Updating CMPv2 config on PKI secret backend %q:\n%v", backend, data)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error updating CMPv2 config for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Updated CMPv2 config on PKI secret backend %q", backend)

	d.SetId(path)

	return pkiSecretBackendConfigCMPV2Read(ctx, d, meta)
}

func pkiSecretBackendConfigCMPV2Read(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	id := d.Id()
	if id == "" {
		return diag.FromErr(fmt.Errorf("no path set for import, id=%q", id))
	}

	backend := strings.TrimSuffix(id, "/config/cmp")
	if err := d.Set("backend", backend); err != nil {
		return diag.FromErr(fmt.Errorf("failed setting field [%s] with value [%v]: %w", "backend", backend, err))
	}

	if err := verifyPkiCMPV2FeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed getting client: %w", err))
	}

	if err := readCMPV2Config(ctx, d, client, id); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func pkiSecretBackendConfigCMPV2Delete(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	// There isn't any delete API for the CMPv2 config.
	return nil
}
