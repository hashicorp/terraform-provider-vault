package vault

import (
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func consulSecretRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: roleWrite,
		Update: roleWrite,
		Read:   roleWrite,
		Delete: roleWrite,

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role",
			},
			"role": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "The role in base64 encoded string",
			},
		},
	}
}

func roleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)
	role := d.Get("role").(string)

	data := map[string]interface{}{
		"policy": role,
	}

	_, err := client.Logical().Write("consul/roles/"+name, data)

	return err
}
