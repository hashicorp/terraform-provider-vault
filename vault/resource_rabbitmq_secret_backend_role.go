package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
			"vhost": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specifies a map of virtual hosts to permissions.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"host": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The vhost to set permissions for.",
						},
						"configure": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The configure permissions for this vhost.",
						},
						"read": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The read permissions for this vhost.",
						},
						"write": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The write permissions for this vhost.",
						},
					},
				},
			},
		},
	}
}

func rabbitmqSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)
	tags := d.Get("tags").(string)
	vhost := d.Get("vhost").([]interface{})

	log.Printf("[DEBUG] Vhosts as list from ResourceData: %+v", vhost)

	vhosts := make(map[string]interface{}, len(vhost))

	for _, host := range vhost {
		h := map[string]interface{}{}
		var id string
		for k, v := range host.(map[string]interface{}) {
			if k == "host" {
				id = v.(string)
				continue
			}
			h[k] = v
		}
		vhosts[id] = h
	}

	log.Printf("[DEBUG] vhosts after munging: %+v", vhosts)

	vhostsJSON, err := json.Marshal(vhosts)
	if err != nil {
		return fmt.Errorf("error serializing vhosts: %s", err)
	}

	log.Printf("[DEBUG] vhosts as JSON: %+v", vhostsJSON)

	data := map[string]interface{}{
		"tags":   tags,
		"vhosts": string(vhostsJSON),
	}
	log.Printf("[DEBUG] Creating role %q on Rabbitmq backend %q", name, backend)
	_, err = client.Logical().Write(backend+"/roles/"+name, data)
	if err != nil {
		return fmt.Errorf("error creating role %q for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created role %q on Rabbitmq backend %q", name, backend)

	d.SetId(backend + "/roles/" + name)
	d.Set("name", name)
	d.Set("tags", tags)
	d.Set("vhost", vhost)
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
	var vhosts []map[string]interface{}
	if v, ok := secret.Data["vhosts"]; ok && v != nil {
		hosts := v.(map[string]interface{})
		for id, val := range hosts {
			vals := val.(map[string]interface{})
			vhosts = append(vhosts, map[string]interface{}{
				"host":      id,
				"configure": vals["configure"],
				"write":     vals["write"],
				"read":      vals["read"],
			})
		}
	}
	d.Set("tags", secret.Data["tags"])
	if err := d.Set("vhost", vhosts); err != nil {
		return fmt.Errorf("Error setting vhosts in state: %s", err)
	}
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
