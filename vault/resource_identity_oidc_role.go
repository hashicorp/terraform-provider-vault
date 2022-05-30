package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityOidcRolePathTemplate = "identity/oidc/role/%s"

func identityOidcRole() *schema.Resource {
	return &schema.Resource{
		Create: identityOidcRoleCreate,
		Update: identityOidcRoleUpdate,
		Read:   identityOidcRoleRead,
		Delete: identityOidcRoleDelete,
		Exists: identityOidcRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the role.",
				Required:    true,
				ForceNew:    true,
			},

			"key": {
				Type:        schema.TypeString,
				Description: "A configured named key, the key must already exist.",
				Required:    true,
				ForceNew:    true,
			},

			"template": {
				Type:        schema.TypeString,
				Description: "The template string to use for generating tokens. This may be in string-ified JSON or base64 format.",
				Optional:    true,
			},

			"ttl": {
				Type:        schema.TypeInt,
				Description: "TTL of the tokens generated against the role in number of seconds.",
				Optional:    true,
				Default:     86400,
			},

			"client_id": {
				Type:        schema.TypeString,
				Description: "The value that will be included in the `aud` field of all the OIDC identity tokens issued by this role",
				Computed:    true,
				Optional:    true,
			},
		},
	}
}

func identityOidcRoleUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	data["key"] = d.Get("key").(string)
	data["client_id"] = d.Get("client_id").(string)
	data["template"] = d.Get("template").(string)
	data["ttl"] = d.Get("ttl").(int)
}

func identityOidcRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	path := identityOidcRolePath(name)

	data := make(map[string]interface{})

	identityOidcRoleUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error writing IdentityOidcRole %s: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote IdentityOidcRole %s to %s", name, path)

	d.SetId(name)

	return identityOidcRoleRead(d, meta)
}

func identityOidcRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Id()
	path := identityOidcRolePath(name)
	log.Printf("[DEBUG] Updating IdentityOidcRole %s at %s", name, path)

	data := map[string]interface{}{}

	identityOidcRoleUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error updating IdentityOidcRole %s: %s", name, err)
	}
	log.Printf("[DEBUG] Updated IdentityOidcRole %q", name)

	return identityOidcRoleRead(d, meta)
}

func identityOidcRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Id()
	path := identityOidcRolePath(name)

	log.Printf("[DEBUG] Reading IdentityOidcRole %s from %s", name, path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading IdentityOidcRole %s: %s", name, err)
	}
	log.Printf("[DEBUG] Read IdentityOidcRole %s", name)
	if resp == nil {
		log.Printf("[WARN] IdentityOidcRole %s not found, removing from state", name)
		d.SetId("")
		return nil
	}

	d.Set("name", name)
	for _, k := range []string{"key", "template", "ttl", "client_id"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on IdentityOidcRole %q: %s", k, path, err)
		}
	}
	return nil
}

func identityOidcRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Id()
	path := identityOidcRolePath(name)

	log.Printf("[DEBUG] Deleting IdentityOidcRole %q", name)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting IdentityOidcRole %s: %s", name, err)
	}
	log.Printf("[DEBUG] Deleted IdentityOidcRole %q", name)

	return nil
}

func identityOidcRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	name := d.Id()
	path := identityOidcRolePath(name)

	log.Printf("[DEBUG] Checking if IdentityOidcRole %q exists", name)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if IdentityOidcRole %s exists: %q", name, err)
	}
	log.Printf("[DEBUG] Checked if IdentityOidcRole %q exists", name)

	return resp != nil, nil
}

func identityOidcRolePath(name string) string {
	return fmt.Sprintf(identityOidcRolePathTemplate, name)
}
