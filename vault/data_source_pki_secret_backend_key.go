// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendKeyDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(readPKISecretBackendKey),
		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where PKI backend is mounted.",
			},
			consts.FieldKeyRef: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Reference to an existing key.",
			},
			consts.FieldKeyName: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the key.",
			},
			consts.FieldKeyID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the key used.",
			},
			consts.FieldKeyType: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Type of the key.",
			},
		},
	}
}

func readPKISecretBackendKey(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	keyRef := d.Get(consts.FieldKeyRef).(string)
	path := fmt.Sprintf("%s/key/%s", backend, keyRef)

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", path)
	if resp == nil {
		return diag.FromErr(fmt.Errorf("no key found at %q", path))
	}

	d.SetId(path)

	keyComputedFields := []string{
		consts.FieldKeyName,
		consts.FieldKeyID,
		consts.FieldKeyType,
	}

	for _, k := range keyComputedFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}
