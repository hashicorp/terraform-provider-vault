package vault

import (
	"fmt"
	"log"
	"encoding/base64"
	"encoding/json"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"strings"
)

func consulRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: consulRoleWrite,
		Update: consulRoleWrite,
		Delete: consulRoleDelete,
		Read:   consulRoleRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the role",
			},

			"role": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "The role document",
			},
			"path": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "consul/roles",
				Description: "Path to mount the consul role at",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.HasSuffix(value, "/") {
						errs = append(errs, fmt.Errorf("path cannot end in '/'"))
					}
					return
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},
		},
	}
}

func consulRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)
	role := d.Get("role").(string)
	userPath := d.Get("path").(string)

	data := make(map[string]interface{})
	encodedRole := base64.StdEncoding.EncodeToString([]byte(role))
	data["policy"] = encodedRole
	data["lease"] = 0
	data["token_type"] = "client"

	path := userPath + name
	log.Printf("[DEBUG] Writing Consul Role %s to Vault", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return consulRoleRead(d, meta)
}

func consulRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Deleting Consul Role from %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}

func consulRoleRead(d *schema.ResourceData, meta interface{}) error {
	path := d.Id()

	client := meta.(*api.Client)

	log.Printf("[DEBUG] Reading %s from Vault", path)
	role, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if role == nil {
		log.Printf("[WARN] consul role (%s) not found, removing from state", path)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] secret: %#v", role)

	jsonDataBytes, err := json.Marshal(role.Data)
	if err != nil {
		return fmt.Errorf("error marshaling JSON for %q: %s", path, err)
	}
	d.Set("data_json", string(jsonDataBytes))
	d.Set("path", path)

	return nil
}
