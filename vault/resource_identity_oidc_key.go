package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityOidcKeyPathTemplate = "identity/oidc/key/%s"

func identityOidcKey() *schema.Resource {
	return &schema.Resource{
		Create: identityOidcKeyCreate,
		Update: identityOidcKeyUpdate,
		Read:   identityOidcKeyRead,
		Delete: identityOidcKeyDelete,
		Exists: identityOidcKeyExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the key.",
				Required:    true,
				ForceNew:    true,
			},

			"rotation_period": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "How often to generate a new signing key in number of seconds",
				Computed:    true,
			},

			"verification_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Controls how long the public portion of a signing key will be available for verification after being rotated in seconds.",
				Computed:    true,
			},

			"algorithm": {
				Type:        schema.TypeString,
				Description: "Signing algorithm to use. This will default to \"RS256\", and is currently the only allowed value.",
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
			},
		},
	}
}

func identityOidcKeyUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	if v, ok := d.GetOk("rotation_period"); ok {
		data["rotation_period"] = v.(int)
	}

	if v, ok := d.GetOk("verification_ttl"); ok {
		data["verification_ttl"] = v.(int)
	}

	if v, ok := d.GetOk("algorithm"); ok {
		data["algorithm"] = v
	}
}

func identityOidcKeyCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	path := identityOidcKeyPath(name)

	data := make(map[string]interface{})

	identityOidcKeyUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error writing IdentityOidcKey %s: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote IdentityOidcKey %s to %s", name, path)

	d.SetId(name)

	return identityOidcKeyRead(d, meta)
}

func identityOidcKeyUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Id()
	path := identityOidcKeyPath(name)
	log.Printf("[DEBUG] Updating IdentityOidcKey %s at %s", name, path)

	data := map[string]interface{}{}

	identityOidcKeyUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error updating IdentityOidcKey %s: %s", name, err)
	}
	log.Printf("[DEBUG] Updated IdentityOidcKey %q", name)

	return identityOidcKeyRead(d, meta)
}

func identityOidcKeyRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Id()
	path := identityOidcKeyPath(name)

	log.Printf("[DEBUG] Reading IdentityOidcKey %s from %s", name, path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading IdentityOidcKey %s: %s", name, err)
	}
	log.Printf("[DEBUG] Read IdentityOidcKey %s", name)
	if resp == nil {
		log.Printf("[WARN] IdentityOidcKey %s not found, removing from state", name)
		d.SetId("")
		return nil
	}

	d.Set("name", name)
	for _, k := range []string{"rotation_period", "verification_ttl", "algorithm"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on IdentityOidcKey %q: %s", k, path, err)
		}
	}
	return nil
}

func identityOidcKeyDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Id()
	path := identityOidcKeyPath(name)

	log.Printf("[DEBUG] Deleting IdentityOidcKey %q", name)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error IdentityOidcKey %q", name)
	}
	log.Printf("[DEBUG] Deleted IdentityOidcKey %q", name)

	return nil
}

func identityOidcKeyExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	name := d.Id()
	path := identityOidcKeyPath(name)

	log.Printf("[DEBUG] Checking if IdentityOidcKey %s exists", name)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if IdentityOidcKey %s exists: %q", name, err)
	}
	log.Printf("[DEBUG] Checked if IdentityOidcKey %s exists", name)

	return resp != nil, nil
}

func identityOidcKeyPath(name string) string {
	return fmt.Sprintf(identityOidcKeyPathTemplate, name)
}
