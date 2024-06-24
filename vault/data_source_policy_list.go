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

func policyListDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: ReadContextWrapper(policyListDataSourceRead),

		Schema: map[string]*schema.Schema{
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

func policyListDataSourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := fmt.Sprintf("/v1/sys/policies/acl?list=true")

	names, err := client.Logical().List(path)
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Read %q from Vault", path)

	if err := d.Set(consts.FieldNames, names); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(path)

	return nil
}
