package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityOIDCOpenIDConfigPathSuffix = "/.well-known/openid-configuration"

func identityOIDCOpenIDConfigDataSource() *schema.Resource {
	return &schema.Resource{
		Read: readOIDCOpenIDConfigResource,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the provider.",
			},
			"openid_config": {
				Type: schema.TypeMap,
				Description: "OpenID Connect Metadata for a named OIDC provider." +
					"The response is a compliant OpenID Provider Configuration Response.",
				Computed: true,
			},
		},
	}
}

func readOIDCOpenIDConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("name").(string)
	path := "/v1/" + getOIDCProviderPath(name) + identityOIDCOpenIDConfigPathSuffix
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

	if err := d.Set("openid_config", secret.Data); err != nil {
		return err
	}

	return nil
}
