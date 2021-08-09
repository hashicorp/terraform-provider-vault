package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityOidcKeyPathTemplate = "identity/oidc/key/%s"

var (
	identityOidcKeyFields = []string{
		"rotation_period",
		"verification_ttl",
		"algorithm",
		"allowed_client_ids",
	}
)

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
				Default:     86400,
			},

			"verification_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Controls how long the public portion of a signing key will be available for verification after being rotated in seconds.",
				Default:     86400,
			},

			"algorithm": {
				Type:        schema.TypeString,
				Description: "Signing algorithm to use. Signing algorithm to use. Allowed values are: RS256 (default), RS384, RS512, ES256, ES384, ES512, EdDSA.",
				Optional:    true,
				Default:     "RS256",
			},

			"allowed_client_ids": {
				Type:        schema.TypeSet,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Array of role client ids allowed to use this key for signing. If empty, no roles are allowed. If \"*\", all roles are allowed.",
				Optional:    true,
				Computed:    true,
			},
		},
	}
}

func identityOidcKeyUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	data["rotation_period"] = d.Get("rotation_period").(int)
	data["verification_ttl"] = d.Get("verification_ttl").(int)
	data["algorithm"] = d.Get("algorithm").(string)

	if d.IsNewResource() || d.HasChange("allowed_client_ids") {
		data["allowed_client_ids"] = d.Get("allowed_client_ids").(*schema.Set).List()
	}
}

func identityOidcKeyCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)
	path := identityOidcKeyPath(name)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := make(map[string]interface{})

	identityOidcKeyUpdateFields(d, data)
	if err := identityOidcKeyApiWrite(name, data, client); err != nil {
		return err
	}

	d.SetId(name)

	return identityOidcKeyRead(d, meta)
}

func identityOidcKeyUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Id()
	path := identityOidcKeyPath(name)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	log.Printf("[DEBUG] Updating IdentityOidcKey %s at %s", name, path)

	data := map[string]interface{}{}

	identityOidcKeyUpdateFields(d, data)
	if err := identityOidcKeyApiWrite(name, data, client); err != nil {
		return err
	}

	return identityOidcKeyRead(d, meta)
}

func identityOidcKeyRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Id()

	resp, err := identityOidcKeyApiRead(name, client)
	if err != nil {
		return fmt.Errorf("error reading IdentityOidcKey %s: %s", name, err)
	}

	if resp == nil {
		log.Printf("[WARN] IdentityOidcKey %s not found, removing from state", name)
		d.SetId("")
		return nil
	}

	d.Set("name", name)
	for _, k := range identityOidcKeyFields {
		if err := d.Set(k, resp[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on IdentityOidcKey %s: %s", k, name, err)
		}
	}
	return nil
}

func identityOidcKeyDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Id()
	path := identityOidcKeyPath(name)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	log.Printf("[DEBUG] Deleting IdentityOidcKey %q", name)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting IdentityOidcKey %s: %s", name, err)
	}
	log.Printf("[DEBUG] Deleted IdentityOidcKey %q", name)

	return nil
}

func identityOidcKeyExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	name := d.Id()

	log.Printf("[DEBUG] Checking if IdentityOidcKey %s exists", name)
	key, err := identityOidcKeyApiRead(name, client)

	if err != nil {
		return true, fmt.Errorf("error checking if IdentityOidcKey %s exists: %q", name, err)
	}
	log.Printf("[DEBUG] Checked if IdentityOidcKey %s exists", name)

	return key != nil, nil
}

func identityOidcKeyPath(name string) string {
	return fmt.Sprintf(identityOidcKeyPathTemplate, name)
}

func identityOidcKeyApiRead(name string, client *api.Client) (map[string]interface{}, error) {
	path := identityOidcKeyPath(name)
	resp, err := client.Logical().Read(path)

	log.Printf("[DEBUG] Reading IdentityOidcKey %s", name)

	// Vault incorrectly returns 400 for deleted key. In the meantime, we will look into
	// the error string to check this.
	// Fixed by https://github.com/hashicorp/vault/pull/7267 and slated for Vault 1.2.2
	if err != nil {
		if !strings.Contains(err.Error(), "no named key found") {
			return nil, fmt.Errorf("error reading IdentityOidcKey %s: %q", name, err)
		}
		// Key was not found and we set `resp` to nil
		resp = nil
	}

	if resp == nil {
		log.Printf("[WARN] IdentityOidcKey %s not found", name)
		return nil, nil
	}

	return resp.Data, nil
}

func identityOidcKeyApiWrite(name string, data map[string]interface{}, client *api.Client) error {
	path := identityOidcKeyPath(name)

	log.Printf("[DEBUG] Writing IdentityOidcKey %s at %s", name, path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing IdentityOidcKey %s: %s", name, err)
	}
	log.Printf("[DEBUG] Wrote IdentityOidcKey %q", name)

	return nil
}
