// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"
	"strings"

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
			"recursive": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "True to fetch all child namespaces.",
			},
			consts.FieldPaths: {
				Type:        schema.TypeSet,
				Computed:    true,
				Description: "Namespace paths.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldPathsFQ: {
				Type:        schema.TypeSet,
				Computed:    true,
				Description: "The fully qualified namespace paths.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func namespacesReadNamespacePaths(ctx context.Context, client *api.Client, namespace string, recursive bool) ([]string, diag.Diagnostics) {
	var allNamespaces []string

	client.SetNamespace(namespace)

	resp, err := client.Logical().ListWithContext(ctx, consts.SysNamespaceRoot)
	if err != nil {
		return nil, diag.Errorf("error reading namespaces from Vault: %v", err)
	}

	prefix := ""
	if namespace != "" {
		prefix = namespace + "/"
	}

	for _, ns := range flattenPaths(resp) {
		allNamespaces = append(allNamespaces, prefix+ns)

		if recursive {
			subNamespaces, diags := namespacesReadNamespacePaths(ctx, client, prefix+ns, true)
			if diags.HasError() {
				return nil, diags
			}
			allNamespaces = append(allNamespaces, subNamespaces...)
		}
	}

	return allNamespaces, nil
}

func namespacesDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	namespace := client.Namespace()
	id := mountutil.NormalizeMountPath(namespace)
	d.SetId(id)

	log.Printf("[DEBUG] Reading namespaces from Vault")

	absolutePaths, diags := namespacesReadNamespacePaths(ctx, client, namespace, d.Get("recursive").(bool))
	if diags.HasError() {
		return diags
	}

	if err := d.Set(consts.FieldPathsFQ, absolutePaths); err != nil {
		return diag.Errorf("error setting %q to state: %v", consts.FieldPathsFQ, err)
	}

	var relativePaths []string
	for _, absolutePath := range absolutePaths {
		relativePaths = append(relativePaths, strings.TrimPrefix(absolutePath, namespace+"/"))
	}

	if err := d.Set(consts.FieldPaths, relativePaths); err != nil {
		return diag.Errorf("error setting %q to state: %v", consts.FieldPaths, err)
	}

	return nil
}

func flattenPaths(resp *api.Secret) []string {
	if resp == nil {
		return nil
	}

	var paths []string
	if keys, ok := resp.Data["keys"]; ok {
		for _, key := range keys.([]interface{}) {
			paths = append(paths, mountutil.TrimSlashes(key.(string)))
		}
	}
	return paths
}
