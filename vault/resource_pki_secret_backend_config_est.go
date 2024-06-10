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

func pkiSecretBackendConfigEstResource() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages Vault PKI EST configuration",
		CreateContext: provider.MountCreateContextWrapper(pkiSecretBackendConfigEstWrite, provider.VaultVersion116),
		UpdateContext: pkiSecretBackendConfigEstWrite,
		ReadContext:   pkiSecretBackendConfigEstRead,
		DeleteContext: pkiSecretBackendConfigEstDelete,
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
				Description: "Specifies whether EST is enabled",
			},
			consts.FieldDefaultMount: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, this mount will register the default `.well-known/est` URL path. Only a single mount can enable this across a Vault cluster",
			},
			consts.FieldDefaultPathPolicy: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Required to be set if default_mount is enabled. Specifies the behavior for requests using the default EST label. Can be sign-verbatim or a role given by role:<role_name>",
			},
			consts.FieldLabelToPathPolicy: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Configures a pairing of an EST label with the redirected behavior for requests hitting that role. The path policy can be sign-verbatim or a role given by role:<role_name>. Labels must be unique across Vault cluster, and will register .well-known/est/<label> URL paths",
			},
			consts.FieldAuthenticators: {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "Lists the mount accessors EST should delegate authentication requests towards",
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

func pkiSecretBackendConfigEstWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := verifyPkiEstFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := pkiSecretBackendConfigEstPath(backend)

	fieldsToSet := []string{
		consts.FieldEnabled,
		consts.FieldDefaultMount,
		consts.FieldDefaultPathPolicy,
		consts.FieldLabelToPathPolicy,
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

	log.Printf("[DEBUG] Updating EST config on PKI secret backend %q:\n%v", backend, data)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error updating EST config for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Updated EST config on PKI secret backend %q", backend)

	d.SetId(path)

	return pkiSecretBackendConfigEstRead(ctx, d, meta)
}

func pkiSecretBackendConfigEstRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	id := d.Id()
	if id == "" {
		return diag.FromErr(fmt.Errorf("no path set for import, id=%q", id))
	}

	backend := strings.TrimSuffix(id, "/config/est")
	if err := d.Set("backend", backend); err != nil {
		return diag.FromErr(fmt.Errorf("failed setting field [%s] with value [%v]: %w", "backend", backend, err))
	}

	if err := verifyPkiEstFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed getting client: %w", err))
	}

	if err := readEstConfig(ctx, d, client, id); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func pkiSecretBackendConfigEstDelete(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	// There isn't any delete API for the EST config.
	return nil
}
