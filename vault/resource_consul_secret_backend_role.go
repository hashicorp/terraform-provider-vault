package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func consulSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: consulSecretBackendRoleCreate,
		Read:   consulSecretBackendRoleRead,
		Update: consulSecretBackendRoleUpdate,
		Delete: consulSecretBackendRoleDelete,
		Exists: consulSecretBackendRoleExists,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of an existing role against which to create this Consul credential",
			},
			"path": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Required:    true,
				Description: "Unique name of the Vault Consul mount to configure",
			},
			"policies": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "List of Consul policies to associate with this role",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func consulSecretBackendRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)
	path := d.Get("path").(string)
	policies := d.Get("policies").([]interface{})

	reqPath := consulSecretBackendRolePath(path, name)

	payload := map[string]interface{}{
		"policies": policies,
	}

	d.Partial(true)
	log.Printf("[DEBUG] Configuring Consul secrets backend role at %q", reqPath)

	d.SetId(path + "," + name)

	if _, err := client.Logical().Write(reqPath, payload); err != nil {
		return fmt.Errorf("Error writing role configuration for %q: %s", reqPath, err)
	}
	d.SetPartial("name")
	d.SetPartial("path")
	d.SetPartial("policies")
	d.Partial(false)

	return nil
}

func consulSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	s := strings.Split(d.Id(), ",")
	path := s[0]
	name := s[1]

	reqPath := consulSecretBackendRolePath(path, name)

	log.Printf("[DEBUG] Reading Consul secrets backend role at %q", reqPath)

	secret, err := client.Logical().Read(reqPath)
	if err != nil {
		return fmt.Errorf("Error reading role configuration for %q: %s", reqPath, err)
	}

	if secret == nil {
		return fmt.Errorf("Resource not found")
	}

	data := secret.Data
	d.Set("name", name)
	d.Set("path", path)
	d.Set("policies", data["policies"])

	return nil
}

func consulSecretBackendRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	s := strings.Split(d.Id(), ",")
	path := s[0]
	name := s[1]

	reqPath := consulSecretBackendRolePath(path, name)

	d.Partial(true)

	if d.HasChange("policies") {
		log.Printf("[DEBUG] Updating role configuration at %q", reqPath)
		policies := d.Get("policies").([]interface{})

		payload := map[string]interface{}{
			"policies": policies,
		}
		if _, err := client.Logical().Write(reqPath, payload); err != nil {
			return fmt.Errorf("Error writing role configuration for %q: %s", reqPath, err)
		}
		log.Printf("[DEBUG] Updated role configuration at %q", reqPath)
		d.SetPartial("policies")
	}

	d.Partial(false)
	return consulSecretBackendRoleRead(d, meta)
}

func consulSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	s := strings.Split(d.Id(), ",")
	path := s[0]
	name := s[1]

	reqPath := consulSecretBackendRolePath(path, name)

	log.Printf("[DEBUG] Deleting Consul backend role at %q", reqPath)

	if _, err := client.Logical().Delete(reqPath); err != nil {
		return fmt.Errorf("Error deleting Consul backend role at %q: %s", reqPath, err)
	}
	log.Printf("[DEBUG] Deleted Consul backend role at %q", reqPath)
	return nil
}

func consulSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	s := strings.Split(d.Id(), ",")
	path := s[0]
	name := s[1]

	reqPath := consulSecretBackendRolePath(path, name)

	log.Printf("[DEBUG] Checking Consul secrets backend role at %q", reqPath)

	secret, err := client.Logical().Read(reqPath)
	if err != nil {
		return false, fmt.Errorf("Error reading role configuration for %q: %s", reqPath, err)
	}

	return secret != nil, nil
}

func consulSecretBackendRolePath(path, name string) string {
	return strings.Trim(path, "/") + "/roles/" + name
}
