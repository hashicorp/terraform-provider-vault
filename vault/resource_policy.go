// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func policyResource() *schema.Resource {
	return &schema.Resource{
		Create: policyCreate,
		Update: policyWrite,
		Delete: policyDelete,
		Read:   provider.ReadWrapper(policyRead),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

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

			consts.FieldAllowOverwrite: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Allow overwriting an existing policy. Defaults to `true` for backwards compatibility purposes.",
				Deprecated:  "Deprecated. Overwriting pre-existing policies will soon be removed. Use 'terraform import' to manage existing policies.",
			},
		},
	}
}

func policyCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Get("name").(string)

	allowOverwrite := d.Get(consts.FieldAllowOverwrite).(bool)

	existing, err := client.Sys().GetPolicy(name)

	if err != nil {
		return fmt.Errorf("error checking for existing policy %q: %s", name, err)
	}

	if existing != "" && !allowOverwrite {
		return fmt.Errorf("policy %q already exists; use terraform import to manage it or set allow_overwrite = true", name)
	}

	return policyWrite(d, meta)
}

func policyWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Get("name").(string)
	policy := d.Get("policy").(string)

	log.Printf("[DEBUG] Writing policy %s to Vault", name)
	err := client.Sys().PutPolicy(name, policy)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(name)

	return policyRead(d, meta)
}

func policyDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()

	log.Printf("[DEBUG] Deleting policy %s from Vault", name)

	err := client.Sys().DeletePolicy(name)
	if err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func policyRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()

	policy, err := client.Sys().GetPolicy(name)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	d.Set("policy", policy)
	d.Set("name", name)

	return nil
}
