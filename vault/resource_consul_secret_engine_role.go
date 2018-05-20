package vault

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func consulSecretRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: roleWrite,
		Update: roleWrite,
		Read:   roleRead,
		Delete: roleDelete,

		Schema: map[string]*schema.Schema{
			"mount": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    false,
				Description: "Name of the Consul secret mount which you have mounted earlier",
			},
			"name": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role",
			},
			"role": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "The role ACL",
			},
		},
	}
}

func roleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	mountName := d.Get("mount").(string)
	name := d.Get("name").(string)
	role := d.Get("role").(string)

	roleBase64Encoded := base64.StdEncoding.EncodeToString([]byte(role))

	data := map[string]interface{}{
		"policy": roleBase64Encoded,
	}

	log.Printf("[DEBUG] Writing Consul role %s to Vault backend %s", role, name)
	_, err := client.Logical().Write(mountName+"/roles/"+name, data)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(name)

	return policyRead(d, meta)
}

func roleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	mountName := d.Get("mount").(string)
	name := d.Id()

	log.Printf("[DEBUG] Deleting role %s from Vault", name)

	_, err := client.Logical().Delete(mountName + "/roles/" + name)
	if err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func roleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	mountName := d.Get("mount").(string)
	name := d.Id()

	role, err := client.Logical().Read(mountName + "/roles/" + name)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	if err != nil {
		return fmt.Errorf("error decoding role: %s", err)
	}

	d.Set("role", role)
	d.Set("name", name)
	d.Set("mount", mountName)

	return nil
}
