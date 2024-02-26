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

func pluginPinnedVersionResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(pluginPinnedVersionWrite, provider.VaultVersion116),
		ReadContext:   provider.ReadContextWrapper(pluginPinnedVersionRead),
		DeleteContext: pluginPinnedVersionDelete,

		Schema: map[string]*schema.Schema{
			consts.FieldType: {
				Type:        schema.TypeString,
				Description: `Type of plugin; one of "auth", "secret", or "database".`,
				Required:    true,
				ForceNew:    true,
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Description: "Name of the plugin.",
				Required:    true,
				ForceNew:    true,
			},
			consts.FieldVersion: {
				Type:        schema.TypeString,
				Description: "Semantic pinned plugin version.",
				Optional:    true,
				ForceNew:    true,
			},
		},
	}
}

func pluginPinnedVersionWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := fmt.Sprintf("sys/plugins/pins/%s/%s", d.Get(consts.FieldType).(string), d.Get(consts.FieldName).(string))

	log.Printf("[DEBUG] Writing pinned plugin version %q", path)
	_, err = client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"version": d.Get(consts.FieldVersion).(string),
	})
	if err != nil {
		return diag.Errorf("error updating pinned plugin version %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote pinned plugin version %q", path)

	d.SetId(path)

	return nil
}

func pluginPinnedVersionRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	resp, err := client.Logical().ReadWithContext(ctx, d.Id())

	if err != nil {
		return diag.Errorf("error reading plugin %q: %s", d.Id(), err)
	}

	d.Set(consts.FieldVersion, resp.Data["version"])

	return nil
}

func pluginPinnedVersionDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	log.Printf("[DEBUG] Removing pinned plugin version %q ", d.Id())
	_, err := client.Logical().DeleteWithContext(ctx, d.Id())
	if err != nil {
		return diag.Errorf("error removing pinned plugin version %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Removed pinned plugin version %q", d.Id())

	return nil
}
