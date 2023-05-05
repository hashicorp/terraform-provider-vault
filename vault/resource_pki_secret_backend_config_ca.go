// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendConfigCAResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pkiSecretBackendConfigCACreate,
		ReadContext:   pkiSecretBackendConfigCARead,
		DeleteContext: pkiSecretBackendConfigCADelete,

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			consts.FieldPemBundle: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The key and certificate PEM bundle.",
				ForceNew:    true,
				Sensitive:   true,
			},
			consts.FieldImportedIssuers: {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed:    true,
				Description: "The issuers imported by the Config CA.",
				ForceNew:    true,
				Sensitive:   true,
			},
			consts.FieldImportedKeys: {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed:    true,
				Description: "The keys imported by the Config CA.",
				ForceNew:    true,
				Sensitive:   true,
			},
		},
	}
}

func pkiSecretBackendConfigCACreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)

	path := pkiSecretBackendConfigCAPath(backend)

	data := map[string]interface{}{
		consts.FieldPemBundle: d.Get(consts.FieldPemBundle).(string),
	}

	log.Printf("[DEBUG] Creating CA config on PKI secret backend %q", backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating CA config for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created CA config on PKI secret backend %q", backend)

	d.SetId(backend)

	isIssuerAPISupported := provider.IsAPISupported(meta, provider.VaultVersion111)
	if isIssuerAPISupported {
		computedFields := []string{consts.FieldImportedKeys, consts.FieldImportedIssuers}
		for _, k := range computedFields {
			if err := d.Set(k, resp.Data[k]); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return pkiSecretBackendConfigCARead(ctx, d, meta)
}

func pkiSecretBackendConfigCARead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendConfigCADelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendConfigCAPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/ca"
}
