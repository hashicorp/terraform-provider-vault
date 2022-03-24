package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityOIDCScopePathPrefix = "identity/oidc/scope"

func identityOIDCScopeResource() *schema.Resource {
	return &schema.Resource{
		Create: identityOIDCScopeCreateUpdate,
		Update: identityOIDCScopeCreateUpdate,
		Read:   identityOIDCScopeRead,
		Delete: identityOIDCScopeDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Description: "The name of the scope. The openid scope name is reserved.",
				Required:    true,
			},
			"template": {
				Type:         schema.TypeString,
				Description:  "The template string for the scope. This may be provided as escaped JSON or base64 encoded JSON.",
				Optional:     true,
				ValidateFunc: ValidateDataJSONFunc("vault_identity_oidc_scope"),
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The scope's description.",
				Optional:    true,
			},
		},
	}
}

func identityOIDCScopeRequestData(d *schema.ResourceData) map[string]interface{} {
	fields := []string{"template", "description"}
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

func getOIDCScopePath(name string) string {
	return fmt.Sprintf("%s/%s", identityOIDCScopePathPrefix, name)
}

func identityOIDCScopeCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("name").(string)
	path := getOIDCScopePath(name)

	_, err := client.Logical().Write(path, identityOIDCScopeRequestData(d))
	if err != nil {
		return fmt.Errorf("error writing OIDC Scope %s, err=%w", path, err)
	}

	log.Printf("[DEBUG] Wrote OIDC Scope to %s", path)

	d.SetId(path)

	return identityOIDCScopeRead(d, meta)
}

func identityOIDCScopeRead(d *schema.ResourceData, meta interface{}) error {
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

	for _, k := range []string{"template", "description"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key %q on OIDC Scope %q, err=%w", k, path, err)
		}
	}

	return nil
}

func identityOIDCScopeDelete(d *schema.ResourceData, meta interface{}) error {
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
