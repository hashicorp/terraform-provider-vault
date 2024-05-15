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
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"

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
			StateContext: func(_ context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
				id := d.Id()
				if id == "" {
					return nil, fmt.Errorf("no path set for import, id=%q", id)
				}

				parts := strings.Split(mountutil.NormalizeMountPath(id), "/")
				if err := d.Set("backend", parts[0]); err != nil {
					return nil, err
				}

				return []*schema.ResourceData{d}, nil
			},
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			consts.FieldEnabled: {
				Type:        schema.TypeBool,
				Required:    true,
				Description: "Is the EST feature enabled",
			},
			consts.FieldDefaultMount: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Is this the cluster's default EST mount",
			},
			consts.FieldDefaultPathPolicy: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The behavior of the default_mount when enabled",
			},
			consts.FieldLabelToPathPolicy: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "A pairing of EST label to the configured EST behavior for it",
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
				Description: "Enable parsing of fields from the provided CSR for Sentinel policies",
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

	authenticators := d.Get(consts.FieldAuthenticators).([]interface{})
	var authenticator interface{}
	if len(authenticators) > 0 {
		authenticator = authenticators[0]
	}

	data := map[string]interface{}{
		consts.FieldEnabled:               d.Get(consts.FieldEnabled).(bool),
		consts.FieldDefaultMount:          d.Get(consts.FieldDefaultMount).(bool),
		consts.FieldDefaultPathPolicy:     d.Get(consts.FieldDefaultPathPolicy).(string),
		consts.FieldLabelToPathPolicy:     d.Get(consts.FieldLabelToPathPolicy).(map[string]interface{}),
		consts.FieldAuthenticators:        authenticator,
		consts.FieldEnableSentinelParsing: d.Get(consts.FieldEnableSentinelParsing).(bool),
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
	return readPKISecretBackendConfigEst(ctx, d, meta)
}

func pkiSecretBackendConfigEstDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := verifyPkiEstFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := pkiSecretBackendConfigEstPath(backend)

	data := map[string]interface{}{
		consts.FieldEnabled:               false,
		consts.FieldDefaultMount:          "",
		consts.FieldDefaultPathPolicy:     "",
		consts.FieldLabelToPathPolicy:     map[string]interface{}{},
		consts.FieldAuthenticators:        map[string]interface{}{},
		consts.FieldEnableSentinelParsing: false,
	}

	log.Printf("[DEBUG] resetting EST config on PKI secret backend %q", backend)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error resetting EST config for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Reset EST config on PKI secret backend %q", backend)

	d.SetId(path)
	return nil
}
