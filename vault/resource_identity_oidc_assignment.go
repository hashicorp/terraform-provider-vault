// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const identityOIDCAssignmentPathPrefix = "identity/oidc/assignment"

func identityOIDCAssignmentResource() *schema.Resource {
	return &schema.Resource{
		Create: identityOIDCAssignmentCreateUpdate,
		Update: identityOIDCAssignmentCreateUpdate,
		Read:   provider.ReadWrapper(identityOIDCAssignmentRead),
		Delete: identityOIDCAssignmentDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Description: "The name of the assignment.",
				Required:    true,
			},
			"entity_ids": {
				Type:        schema.TypeSet,
				Description: "A list of Vault entity IDs.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"group_ids": {
				Type:        schema.TypeSet,
				Description: "A list of Vault group IDs.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
		},
	}
}

func identityOIDCAssignmentRequestData(d *schema.ResourceData) map[string]interface{} {
	fields := []string{"entity_ids", "group_ids"}
	data := map[string]interface{}{}

	for _, k := range fields {
		if d.IsNewResource() {
			if v, ok := d.GetOk(k); ok {
				data[k] = v.(*schema.Set).List()
			}
		} else if d.HasChange(k) {
			v := d.Get(k)
			data[k] = v.(*schema.Set).List()
		}
	}

	return data
}

func getOIDCAssignmentPath(name string) string {
	return fmt.Sprintf("%s/%s", identityOIDCAssignmentPathPrefix, name)
}

func identityOIDCAssignmentCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	name := d.Get("name").(string)
	path := getOIDCAssignmentPath(name)

	_, err := client.Logical().Write(path, identityOIDCAssignmentRequestData(d))
	if err != nil {
		return fmt.Errorf("error writing OIDC Assignment %s, err=%w", path, err)
	}

	log.Printf("[DEBUG] Wrote OIDC Assignment to %s", path)

	d.SetId(path)

	return identityOIDCAssignmentRead(d, meta)
}

func identityOIDCAssignmentRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := d.Id()

	log.Printf("[DEBUG] Reading OIDC Assignment for %s", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading OIDC Assignment for %s: %s", path, err)
	}

	log.Printf("[DEBUG] Read OIDC Assignment for %s", path)
	if resp == nil {
		log.Printf("[WARN] OIDC Assignment %s not found, removing from state", path)
		d.SetId("")
		return nil
	}

	for _, k := range []string{"entity_ids", "group_ids"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key %q on OIDC Assignment %q, err=%w", k, path, err)
		}
	}

	return nil
}

func identityOIDCAssignmentDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting OIDC Assignment %s", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting OIDC Assignment %q", path)
	}

	log.Printf("[DEBUG] Deleted OIDC Assignment %q", path)

	return nil
}
