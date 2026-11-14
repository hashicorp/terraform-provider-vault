// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var aclRoleFields = []string{
	"policy",
	"name",
}

func policyAclDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(policyAclDataSourceRead),

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the policy",
			},
			"policy": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Content of the policy",
			},
		},
	}
}

func policyAclDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Get("name").(string)
	path := fmt.Sprintf("/sys/policies/acl/%s", name)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read policy %q from Vault", path)

	d.SetId(path)
	for _, k := range aclRoleFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for policy %q: %q", k, path, err)
			}
		}
	}

	return nil
}
