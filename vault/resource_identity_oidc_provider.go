package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityOIDCProviderPathPrefix = "identity/oidc/provider"

func identityOIDCProviderResource() *schema.Resource {
	return &schema.Resource{
		Create: identityOIDCProviderCreateUpdate,
		Update: identityOIDCProviderCreateUpdate,
		Read:   identityOIDCProviderRead,
		Delete: identityOIDCProviderDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Description: "The name of the provider.",
				Required:    true,
			},
			"issuer": {
				Type: schema.TypeString,
				Description: "Specifies what will be used as the 'scheme://host:port' component for the 'iss' claim of ID tokens." +
					"If provided explicitly, it must point to a Vault instance that is network reachable by clients for ID token validation.",
				Computed: true,
			},
			"allowed_client_ids": {
				Type: schema.TypeSet,
				Description: "The client IDs that are permitted to use the provider. If empty, no clients are allowed. " +
					"If \"*\", all clients are allowed.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"scopes_supported": {
				Type:        schema.TypeSet,
				Description: "The scopes available for requesting on the provider.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
		},
	}
}

func identityOIDCProviderRequestData(d *schema.ResourceData) map[string]interface{} {
	fields := []string{"issuer", "allowed_client_ids", "scopes_supported"}
	data := map[string]interface{}{}
	for _, k := range fields {
		if v, ok := d.GetOk(k); ok {
			if k == "allowed_client_ids" || k == "scopes_supported" {
				data[k] = v.(*schema.Set).List()
				continue
			}
			data[k] = v
		}
	}

	return data
}

func getOIDCProviderPath(name string) string {
	return fmt.Sprintf("%s/%s", identityOIDCProviderPathPrefix, name)
}

func identityOIDCProviderCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("name").(string)
	path := getOIDCProviderPath(name)

	_, err := client.Logical().Write(path, identityOIDCProviderRequestData(d))
	if err != nil {
		return fmt.Errorf("error writing OIDC Provider %s, err=%w", path, err)
	}

	log.Printf("[DEBUG] Wrote OIDC Provider to %s", path)

	d.SetId(path)

	return identityOIDCProviderRead(d, meta)
}

func identityOIDCProviderRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading OIDC Provider for %s", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading OIDC Provider for %s: %s", path, err)
	}

	log.Printf("[DEBUG] Read OIDC Provider for %s", path)
	if resp == nil {
		log.Printf("[WARN] OIDC Provider %s not found, removing from state", path)
		d.SetId("")

		return nil
	}

	for _, k := range []string{"issuer", "allowed_client_ids", "scopes_supported"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key %q on OIDC Provider %q, err=%w", k, path, err)
		}
	}

	return nil
}

func identityOIDCProviderDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting OIDC Provider %s", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting OIDC Provider %q", path)
	}

	log.Printf("[DEBUG] Deleted OIDC Provider %q", path)

	return nil
}
