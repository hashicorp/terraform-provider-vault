// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func mountsDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(mountsDataSourceRead),
		Schema: map[string]*schema.Schema{
			"mounts": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Liste des mounts activés dans Vault",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"accessor": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Internal accessor for the mount.",
						},
						"description": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Human-readable description of the mount.",
						},
						"local": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "True if the mount is local to this Vault node.",
						},
						"options": {
							Type:        schema.TypeMap,
							Computed:    true,
							Description: "Key-value options that configure the mount.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"path": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Full path of the mount, ending with a slash (/).",
						},
						"seal_wrap": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Indicates whether seal wrapping is enabled for this mount.",
						},
						"type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Backend type of the mount (e.g., kv, pki).",
						},
						"uuid": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Unique identifier (UUID) of the mount.",
						},
					},
				},
			},
		},
	}
}

func mountsDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	mounts, err := client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return diag.FromErr(err)
	}

	paths := make([]string, 0, len(mounts))
	for path := range mounts {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	result := make([]map[string]any, 0, len(paths))
	for _, path := range paths {
		m := mounts[path]
		result = append(result, map[string]any{
			"accessor":    m.Accessor,
			"description": m.Description,
			"local":       m.Local,
			"options":     m.Options,
			"path":        path,
			"seal_wrap":   m.SealWrap,
			"type":        m.Type,
			"uuid":        m.UUID,
		})
	}

	if err := d.Set("mounts", result); err != nil {
		return diag.FromErr(err)
	}

	d.SetId("vault-mounts")
	return nil
}
