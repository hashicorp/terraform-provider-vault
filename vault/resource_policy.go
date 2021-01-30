package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func policyResource() *schema.Resource {
	return &schema.Resource{
		Create: policyCreate,
		Update: policyWrite,
		Delete: policyDelete,
		Read:   policyRead,
		Exists: policyExists,
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
		},
	}
}

func policyCreate(d *schema.ResourceData, meta interface{}) error {
	exists, err := policyExists(d, meta)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("policy %s is already exists", d.Get("name").(string))
	}

	err = policyWrite(d, meta)
	if err != nil {
		return err
	}

	return nil
}

func policyWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

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
	client := meta.(*api.Client)

	name := d.Id()

	log.Printf("[DEBUG] Deleting policy %s from Vault", name)

	err := client.Sys().DeletePolicy(name)
	if err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func policyRead(d *schema.ResourceData, meta interface{}) error {
	exists, err := policyExists(d, meta)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("policy %s is not exists", d.Id())
	}

	client := meta.(*api.Client)

	name := d.Id()

	policy, err := client.Sys().GetPolicy(name)

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	d.Set("policy", policy)
	d.Set("name", name)

	return nil
}

func policyExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	policy, err := client.Sys().GetPolicy(name)

	if err != nil {
		return false, fmt.Errorf("error reading from Vault: %s", err)
	}
	return policy != "", nil
}
