package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityOIDCAssignmentPathTemplate = "identity/oidc/assignment"

func identityOIDCAssignmentResource() *schema.Resource {
	return &schema.Resource{
		Create: identityOIDCAssignmentCreateUpdate,
		Update: identityOIDCAssignmentCreateUpdate,
		Read:   identityOIDCAssignmentRead,
		Delete: identityOIDCAssignmentDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Description: "The name of the assignment.",
				Required:    true,
			},
			"entity_ids": {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "A list of Vault entity IDs.",
				Optional:    true,
			},
			"group_ids": {
				Type:        schema.TypeList,
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
				data[k] = v
			}
		} else if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	return data
}

func getOIDCAssignmentPath(name string) string {
	return fmt.Sprintf("%s/%s", identityOIDCAssignmentPathTemplate, name)
}

func identityOIDCAssignmentCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("name").(string)
	path := getOIDCAssignmentPath(name)

	data := identityOIDCAssignmentRequestData(d)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing OIDC Assignment %s, err=%w", path, err)
	}
	log.Printf("[DEBUG] Wrote OIDC Assignment to %s", path)

	d.SetId(path)

	return identityOIDCAssignmentRead(d, meta)
}

func identityOIDCAssignmentRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
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
			return fmt.Errorf("error setting state key \"%s\" on OIDC Assignment %s, err=%w", k, path, err)
		}
	}
	return nil
}

func identityOIDCAssignmentDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting OIDC Assignment %s", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting OIDC Assignment %q", path)
	}
	log.Printf("[DEBUG] Deleted OIDC Assignment %q", path)

	return nil
}
