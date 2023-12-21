// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldKeyVaultURI = "key_vault_uri"
	fieldCloud       = "cloud"
)

var azureSyncDestinationFields = []string{
	fieldKeyVaultURI,
	fieldCloud,
	consts.FieldClientID,
	consts.FieldClientSecret,
	consts.FieldTenantID,
}

func azureSecretsSyncDestinationResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(azureSecretsSyncDestinationWrite, provider.VaultVersion115),
		ReadContext:   provider.ReadContextWrapper(azureSecretsSyncDestinationRead),
		DeleteContext: azureSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the Azure destination.",
				ForceNew:    true,
			},
			fieldKeyVaultURI: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "URI of an existing Azure Key Vault instance.",
				ForceNew:    true,
			},
			consts.FieldClientID: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Client ID of an Azure app registration.",
				ForceNew:    true,
			},
			consts.FieldClientSecret: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Client Secret of an Azure app registration.",
				ForceNew:    true,
			},
			consts.FieldTenantID: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "ID of the target Azure tenant.",
				ForceNew:    true,
			},
			fieldCloud: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a cloud for the client.",
				ForceNew:    true,
			},
		},
	}
}

func azureSecretsSyncDestinationWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	path := azureSecretsSyncDestinationPath(name)

	data := map[string]interface{}{}

	for _, k := range azureSyncDestinationFields {
		data[k] = d.Get(k)
	}

	log.Printf("[DEBUG] Writing Azure sync destination to %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error enabling Azure sync destination %q: %s", path, err)
	}
	log.Printf("[DEBUG] Enabled Azure sync destination %q", path)

	d.SetId(name)

	return azureSecretsSyncDestinationRead(ctx, d, meta)
}

func azureSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	name := d.Id()
	path := azureSecretsSyncDestinationPath(name)

	log.Printf("[DEBUG] Reading Azure sync destination")
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading Azure sync destination from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Azure sync destination")

	if resp == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range azureSyncDestinationFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error setting state key %q: err=%s", k, err)
			}
		}
	}

	return nil
}

func azureSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := azureSecretsSyncDestinationPath(d.Id())

	log.Printf("[DEBUG] Deleting Azure sync destination at %q", path)
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error deleting Azure sync destination at %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted Azure sync destination at %q", path)

	return nil
}

func azureSecretsSyncDestinationPath(name string) string {
	return "sys/sync/destinations/azure-kv/" + name
}
