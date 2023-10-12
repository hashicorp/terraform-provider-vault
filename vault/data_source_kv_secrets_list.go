// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func kvSecretListDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(kvSecretListDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Full KV-V1 path where secrets will be listed.",
				ValidateFunc: provider.ValidateNoTrailingSlash,
			},

			consts.FieldNames: {
				Type:        schema.TypeList,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of all secret names.",
				Sensitive:   true,
			},
		},
	}
}

func kvSecretListDataSourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)

	names, err := kvListRequest(client, path)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldNames, names); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(path)

	return nil
}
