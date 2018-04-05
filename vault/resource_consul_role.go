package vault

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
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
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the role",
			},
			"policy": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The policy document",
			},
			"token_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "client",
				Description: "Consul token type",
			},
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "consul",
				Description: "Path to the consul secret backend mount. Default is just \"consul\".",
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
	policy := d.Get("policy").(string)
	tokenType := d.Get("token_type").(string)
	userPath := d.Get("path").(string)

	data := map[string]interface{}{
		"policy":     base64.StdEncoding.EncodeToString([]byte(policy)),
		"lease":      0,
		"token_type": tokenType,
	}

	path := userPath + "/roles/" + name
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

	log.Printf("[DEBUG] Reading Consul role %s from Vault", path)
	role, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if role == nil {
		log.Printf("[WARN] consul role (%s) not found, removing from state", path)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] consul role: %#v", role)
	tokenType := role.Data["token_type"].(string)
	d.Set("token_type", tokenType)
	if tokenType == "client" {
		encodedPolicy := role.Data["policy"].(string)
		policy, err := base64.StdEncoding.DecodeString(encodedPolicy)
		if err != nil {
			return fmt.Errorf("error decoding consul policy: %s", err)
		}

		d.Set("policy", string(policy))
	}

	return nil
}
