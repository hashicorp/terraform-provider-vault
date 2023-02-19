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
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func namespaceDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(namespaceDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Description:  "Namespace path.",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			consts.FieldNamespaceID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Namespace ID.",
			},
			consts.FieldPathFQ: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The fully qualified namespace path.",
			},
			consts.FieldCustomMetadata: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Metadata associated with this namespace.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func namespaceDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	var path string
	if v, ok := d.GetOk(consts.FieldPath); ok {
		path = v.(string)
	} else {
		log.Printf("[DEBUG] Returning current namespace")
		providerNS := client.Namespace()
		return namespaceDataSourceReadCurrent(d, providerNS)
	}

	log.Printf("[DEBUG] Reading namespace %q from Vault", path)

	resp, err := client.Logical().Read(consts.SysNamespaceRoot + path)
	if err != nil {
		return diag.Errorf("error reading namespace %q from Vault: %s", path, err)
	}
	if resp == nil {
		return diag.Errorf("namespace %q not found", path)
	}

	d.SetId(resp.Data[consts.FieldPath].(string))

	d.Set(consts.FieldNamespaceID, resp.Data["id"])
	d.Set(consts.FieldPath, mountutil.TrimSlashes(path))

	pathFQ := path
	if parent, ok := d.GetOk(consts.FieldNamespace); ok {
		pathFQ = strings.Join([]string{parent.(string), path}, "/")
	}
	d.Set(consts.FieldPathFQ, pathFQ)

	if v, ok := resp.Data["custom_metadata"]; ok {
		d.Set(consts.FieldCustomMetadata, v)
	}

	return nil
}

func namespaceDataSourceReadCurrent(d *schema.ResourceData, providerNS string) diag.Diagnostics {
	id := mountutil.NormalizeMountPath(providerNS)
	d.SetId(id)

	d.Set(consts.FieldPath, "")

	pathFQ := ""
	if parent, ok := d.GetOk(consts.FieldNamespace); ok {
		pathFQ = parent.(string)
	}
	d.Set(consts.FieldPathFQ, pathFQ)

	return nil
}
