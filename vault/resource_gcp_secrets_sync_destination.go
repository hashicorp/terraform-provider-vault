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

var gcpSyncDestinationFields = []string{
	consts.FieldCredentials,
}

func gcpSecretsSyncDestinationResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(gcpSecretsSyncDestinationWrite, provider.VaultVersion115),
		ReadContext:   provider.ReadContextWrapper(gcpSecretsSyncDestinationRead),
		DeleteContext: gcpSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the GCP destination.",
				ForceNew:    true,
			},
			consts.FieldCredentials: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "JSON credentials (either file contents or '@path/to/file').",
				ForceNew:    true,
			},
		},
	}
}

func gcpSecretsSyncDestinationWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	path := gcpSecretsSyncDestinationPath(name)

	data := map[string]interface{}{}

	for _, k := range gcpSyncDestinationFields {
		data[k] = d.Get(k)
	}

	log.Printf("[DEBUG] Writing GCP sync destination to %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error enabling GCP sync destination %q: %s", path, err)
	}
	log.Printf("[DEBUG] Enabled GCP sync destination %q", path)

	d.SetId(name)

	return gcpSecretsSyncDestinationRead(ctx, d, meta)
}

func gcpSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	name := d.Id()
	path := gcpSecretsSyncDestinationPath(name)

	log.Printf("[DEBUG] Reading GCP sync destination")
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading GCP sync destination from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read GCP sync destination")

	if resp == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	// set sensitive fields that will not be returned from Vault
	if err := d.Set(consts.FieldCredentials, d.Get(consts.FieldCredentials).(string)); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func gcpSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := gcpSecretsSyncDestinationPath(d.Id())

	log.Printf("[DEBUG] Deleting GCP sync destination at %q", path)
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error deleting GCP sync destination at %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted GCP sync destination at %q", path)

	return nil
}

func gcpSecretsSyncDestinationPath(name string) string {
	return "sys/sync/destinations/gcp-sm/" + name
}
