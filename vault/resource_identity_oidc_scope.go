package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityOidcScopePathTemplate = "identity/oidc/scope"

func identityOidcScopeResource() *schema.Resource {
	return &schema.Resource{
		Create: identityOidcScopeCreateUpdate,
		Update: identityOidcScopeCreateUpdate,
		Read:   identityOidcScopeRead,
		Delete: identityOidcScopeDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Description: "The name of the scope. This parameter is specified as part of the URL. The openid scope name is reserved.",
				Required:    true,
			},
			"template": {
				Type:        schema.TypeString,
				Description: "The template string for the scope. This may be provided as escaped JSON or base64 encoded JSON.",
				Optional:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "A description of the scope.",
				Optional:    true,
			},
		},
	}
}

func identityOidcScopeRequestData(d *schema.ResourceData) map[string]interface{} {
	fields := []string{"name", "template", "description"}
	data := map[string]interface{}{}

	for _, k := range fields {
		if d.IsNewResource() {
			if v, ok := d.GetOk(k); ok {
				data[k] = v
			}
		} else if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	return data
}

func getOidcScopePath(name string) string {
	return fmt.Sprintf("%s/%s", identityOidcScopePathTemplate, name)
}

func identityOidcScopeCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	data := identityOidcScopeRequestData(d)
	name := d.Get("name").(string)

	path := getOidcScopePath(name)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing OIDC Scope %s, err=%w", path, err)
	}
	log.Printf("[DEBUG] Wrote OIDC Scope to %s", path)

	d.SetId(path)

	// TODO confirm if this is correct; Vault does not return 'name' in response
	if d.IsNewResource() {
		d.Set("name", name)
	}

	return identityOidcScopeRead(d, meta)
}

func identityOidcScopeRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading OIDC Scope for %s", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading OIDC Scope for %s: %s", path, err)
	}
	log.Printf("[DEBUG] Read OIDC Scope for %s", path)
	if resp == nil {
		log.Printf("[WARN] OIDC Scope %s not found, removing from state", path)
		d.SetId("")
		return nil
	}

	// TODO Vault doesn't return 'name'; confirm behavior
	for _, k := range []string{"template", "description"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on OIDC Scope %s, err=%w", k, path, err)
		}
	}
	return nil
}

func identityOidcScopeDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting OIDC Scope %s", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting OIDC Scope %q", path)
	}
	log.Printf("[DEBUG] Deleted OIDC Scope %q", path)

	return nil
}
