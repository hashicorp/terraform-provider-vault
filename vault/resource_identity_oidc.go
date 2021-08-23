package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const identityOidcPathTemplate = "identity/oidc/config"

func identityOidc() *schema.Resource {
	return &schema.Resource{
		Create: identityOidcCreate,
		Update: identityOidcUpdate,
		Read:   identityOidcRead,
		Delete: identityOidcDelete,
		Exists: identityOidcExists,

		Schema: map[string]*schema.Schema{
			"issuer": {
				Type:        schema.TypeString,
				Description: "Issuer URL to be used in the iss claim of the token. If not set, Vault's api_addr will be used. The issuer is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components, but no query or fragment components.",
				Optional:    true,
				Computed:    true,
			},
		},
	}
}

func identityOidcUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	data["issuer"] = d.Get("issuer").(string)
}

func identityOidcCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*util.Client)
	path := identityOidcPathTemplate

	data := make(map[string]interface{})
	addr, err := client.Address()
	if err != nil {
		return fmt.Errorf("error get client address: %w", err)
	}

	identityOidcUpdateFields(d, data)

	if _, err := client.Logical().Write(path, data); err != nil {
		return fmt.Errorf("error writing IdentityOidc %s: %w", addr, err)
	}
	log.Printf("[DEBUG] Wrote IdentityOidc to %s", addr)

	d.SetId(addr)

	return identityOidcRead(d, meta)
}

func identityOidcUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*util.Client)
	path := identityOidcPathTemplate
	addr := d.Id()

	log.Printf("[DEBUG] Updating IdentityOidc for %s", addr)

	data := map[string]interface{}{}

	identityOidcUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating IdentityOidc for %s: %s", addr, err)
	}
	log.Printf("[DEBUG] Updated IdentityOidc for %q", addr)

	return identityOidcRead(d, meta)
}

func identityOidcRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*util.Client)
	path := identityOidcPathTemplate
	addr := d.Id()

	log.Printf("[DEBUG] Reading IdentityOidc for %s", addr)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading IdentityOidc for %s: %s", addr, err)
	}
	log.Printf("[DEBUG] Read IdentityOidc for %s", addr)
	if resp == nil {
		log.Printf("[WARN] IdentityOidc %s not found, removing from state", addr)
		d.SetId("")
		return nil
	}

	for _, k := range []string{"issuer"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on IdentityOidc %q: %s", k, addr, err)
		}
	}
	return nil
}

func identityOidcDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*util.Client)
	addr := d.Id()
	path := identityOidcPathTemplate

	log.Printf("[DEBUG] Reseting IdentityOidc for %q back to defaults", addr)

	d.Set("issuer", "")
	data := map[string]interface{}{}
	identityOidcUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error resetting IdentityOidc %s, %s", addr, err)
	}
	log.Printf("[DEBUG] Finished resetting IdentityOidc for %q", addr)

	return nil
}

func identityOidcExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*util.Client)
	addr := d.Id()
	path := identityOidcPathTemplate

	log.Printf("[DEBUG] Checking if IdentityOidc for %q is set", addr)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if IdentityOidc for %q is set: %s", addr, err)
	}
	log.Printf("[DEBUG] Checked if IdentityOidc for %q is set", addr)

	return resp.Data["issuer"].(string) != "", nil
}
