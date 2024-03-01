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

func pluginPinnedVersionResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(pluginPinnedVersionWrite, provider.VaultVersion116),
		UpdateContext: provider.UpdateContextWrapper(pluginPinnedVersionWrite, provider.VaultVersion116),
		ReadContext:   provider.ReadContextWrapper(pluginPinnedVersionRead),
		DeleteContext: pluginPinnedVersionDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

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
				Required:    true,
			},
		},
	}
}

func pluginPinnedVersionWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	id := fmt.Sprintf("%s/%s", d.Get(consts.FieldType).(string), d.Get(consts.FieldName).(string))

	log.Printf("[DEBUG] Writing pinned plugin version %q", id)
	_, err = client.Logical().WriteWithContext(ctx, idToPath(id), map[string]interface{}{
		"version": d.Get(consts.FieldVersion).(string),
	})
	if err != nil {
		return diag.Errorf("error updating pinned plugin version %q: %s", id, err)
	}
	log.Printf("[DEBUG] Wrote pinned plugin version %q", id)

	d.SetId(id)

	return nil
}

func pluginPinnedVersionRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	typeAndName := d.Id()
	parts := strings.Split(typeAndName, "/")
	if len(parts) != 2 {
		return diag.Errorf("invalid pinned plugin version ID %q, must be of form <type>/<name>", typeAndName)
	}
	typ, name := parts[0], parts[1]

	resp, err := client.Logical().ReadWithContext(ctx, idToPath(d.Id()))

	if err != nil {
		return diag.Errorf("error reading plugin %q: %s", d.Id(), err)
	}

	if err := d.Set(consts.FieldType, typ); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldVersion, resp.Data["version"]); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func pluginPinnedVersionDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	log.Printf("[DEBUG] Removing pinned plugin version %q ", d.Id())
	_, err := client.Logical().DeleteWithContext(ctx, idToPath(d.Id()))
	if err != nil {
		return diag.Errorf("error removing pinned plugin version %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Removed pinned plugin version %q", d.Id())

	return nil
}

func idToPath(id string) string {
	return fmt.Sprintf("sys/plugins/pins/%s", id)
}
