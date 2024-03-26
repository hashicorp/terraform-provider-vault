// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func namespacesDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(namespacesDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldPaths: {
				Type:        schema.TypeSet,
				Computed:    true,
				Description: "Namespace paths.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func namespacesDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	log.Printf("[DEBUG] Reading namespaces from Vault")

	resp, err := client.Logical().ListWithContext(ctx, consts.SysNamespaceRoot)
	if err != nil {
		return diag.Errorf("error reading namespaces from Vault: %s", err)
	}
	if err := d.Set(consts.FieldPaths, flattenPaths(resp)); err != nil {
		return diag.Errorf("error setting %q to state: %s", consts.FieldPaths, err)
	}

	id := mountutil.NormalizeMountPath(client.Namespace())
	d.SetId(id)

	return nil
}

func flattenPaths(resp *api.Secret) []interface{} {
	if resp == nil {
		return nil
	}

	paths := []interface{}{}
	if keys, ok := resp.Data["keys"]; ok {
		for _, key := range keys.([]interface{}) {
			paths = append(paths, mountutil.TrimSlashes(key.(string)))
		}
	}
	return paths
}
