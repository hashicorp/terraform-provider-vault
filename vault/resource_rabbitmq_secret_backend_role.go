package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func rabbitmqSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: rabbitmqSecretBackendRoleWrite,
		Read:   rabbitmqSecretBackendRoleRead,
		Update: rabbitmqSecretBackendRoleWrite,
		Delete: rabbitmqSecretBackendRoleDelete,
		Exists: rabbitmqSecretBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the role.",
			},
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the Rabbitmq Secret Backend the role belongs to.",
			},
			"tags": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Specifies a comma-separated RabbitMQ management tags.",
			},
			"vhosts": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a map of virtual hosts to permissions.",
				Default:     "",
			},
		},
	}
}

func rabbitmqSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)
	tags := d.Get("tags").(string)
	vhosts := d.Get("vhosts").(string)

	data := map[string]interface{}{
		"tags":   tags,
		"vhosts": vhosts,
	}
	log.Printf("[DEBUG] Creating role %q on Rabbitmq backend %q", name, backend)
	_, err := client.Logical().Write(backend+"/roles/"+name, data)
	if err != nil {
		return fmt.Errorf("error creating role %q for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created role %q on Rabbitmq backend %q", name, backend)

	d.SetId(backend + "/roles/" + name)
	d.Set("name", name)
	d.Set("tags", tags)
	d.Set("vhosts", vhosts)
	d.Set("backend", backend)
	return rabbitmqSecretBackendRoleRead(d, meta)
}

func rabbitmqSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	pathPieces := strings.Split(path, "/")
	if len(pathPieces) < 3 || pathPieces[len(pathPieces)-2] != "roles" {
		return fmt.Errorf("invalid id %q; must be {backend}/roles/{name}", path)
	}

	log.Printf("[DEBUG] Reading role from %q", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read role from %q", path)
	if secret == nil {
		log.Printf("[WARN] Role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	d.Set("tags", secret.Data["tags"])
	d.Set("vhosts", secret.Data["vhosts"])
	d.Set("backend", strings.Join(pathPieces[:len(pathPieces)-2], "/"))
	d.Set("name", pathPieces[len(pathPieces)-1])
	return nil
}

func rabbitmqSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Deleting role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted role %q", path)
	return nil
}

func rabbitmqSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return secret != nil, nil
}
