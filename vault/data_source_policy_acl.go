// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func policyAclDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(policyAclDataSourceRead),

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the policy",
			},

			"policy": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The policy document",
			},
		},
	}
}

func policyAclDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Get("policy_name").(string)
	path := fmt.Sprintf("/sys/policies/acl/%s", name)

	policy, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read policy %q from Vault", path)

	if policy == nil {
		return fmt.Errorf("no policy name found at %q", path)
	}

	d.SetId(path)
	d.Set("name", policy.Data["name"].(string))
	d.Set("policy", policy.Data["policy"].(string))

	return nil
}
