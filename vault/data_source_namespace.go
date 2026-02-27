// Copyright IBM Corp. 2016, 2025
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
		log.Printf("[DEBUG] namespace path not set in config, returning current Vault client namespace")
		providerNS := client.Namespace()
		return namespaceDataSourceReadCurrent(d, providerNS)
	}

	log.Printf("[DEBUG] Reading namespace %q from Vault", path)

	resp, err := client.Logical().ReadWithContext(ctx, consts.SysNamespaceRoot+path)
	if err != nil {
		return diag.Errorf("error reading namespace %q from Vault: %s", path, err)
	}
	if resp == nil {
		return diag.Errorf("namespace %q not found", path)
	}

	d.SetId(resp.Data[consts.FieldPath].(string))

	if err := d.Set(consts.FieldNamespaceID, resp.Data["id"]); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldPath, mountutil.TrimSlashes(path)); err != nil {
		return diag.FromErr(err)
	}

	pathFQ := path
	if parent, ok := d.GetOk(consts.FieldNamespace); ok {
		pathFQ = strings.Join([]string{parent.(string), path}, "/")
	}
	if err := d.Set(consts.FieldPathFQ, pathFQ); err != nil {
		return diag.FromErr(err)
	}

	if v, ok := resp.Data["custom_metadata"]; ok {
		if err := d.Set(consts.FieldCustomMetadata, v); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func namespaceDataSourceReadCurrent(d *schema.ResourceData, providerNS string) diag.Diagnostics {
	id := mountutil.NormalizeMountPath(providerNS)
	d.SetId(id)

	if err := d.Set(consts.FieldPath, ""); err != nil {
		return diag.FromErr(err)
	}

	pathFQ := ""
	if parent, ok := d.GetOk(consts.FieldNamespace); ok {
		pathFQ = parent.(string)
	}
	if err := d.Set(consts.FieldPathFQ, pathFQ); err != nil {
		return diag.FromErr(err)
	}

	return nil
}
