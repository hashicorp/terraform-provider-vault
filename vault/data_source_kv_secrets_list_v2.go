// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func kvSecretListDataSourceV2() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(kvSecretV2ListDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldMount: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path where KV-V2 engine is mounted",
			},

			consts.FieldName: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Full named path of the secret. For a nested secret, " +
					"the name is the nested path excluding the mount and data " +
					"prefix. For example, for a secret at 'kvv2/data/foo/bar/baz', " +
					"the name is 'foo/bar/baz'",
			},

			consts.FieldPath: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Full path where the KV-V2 secrets are listed.",
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

func kvSecretV2ListDataSourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	mount := d.Get(consts.FieldMount).(string)
	name := d.Get(consts.FieldName).(string)

	path := getKVV2Path(mount, name, consts.FieldMetadata)

	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}

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
