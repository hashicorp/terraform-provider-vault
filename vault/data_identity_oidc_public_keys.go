package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityOIDCPublicKeysPathSuffix = "/.well-known/keys"

func identityOIDCPublicKeysDataSource() *schema.Resource {
	return &schema.Resource{
		Read: readOIDCPublicKeysResource,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the provider.",
			},
			"keys": {
				Type: schema.TypeList,
				Description: "The public portion of keys for an OIDC provider. " +
					"Clients can use them to validate the authenticity of an identity token.",
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeMap,
				},
			},
		},
	}
}

func readOIDCPublicKeysResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("name").(string)
	path := "/v1/" + getOIDCProviderPath(name) + identityOIDCPublicKeysPathSuffix
	r := client.NewRequest("GET", path)

	resp, err := client.RawRequest(r)
	if err != nil {
		return fmt.Errorf("error performing GET at %s, err=%w", path, err)
	}
	if resp != nil {
		defer resp.Body.Close()
	}

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return fmt.Errorf("error parsing JSON data from response body, err=%w", err)
	}

	log.Printf("[DEBUG] Read %q from Vault", path)

	d.SetId(path)

	if err := d.Set("keys", secret.Data["keys"]); err != nil {
		return err
	}

	return nil
}
