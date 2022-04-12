package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func identityOIDCClientCredsDataSource() *schema.Resource {
	return &schema.Resource{
		Read: readOIDCClientCredsResource,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the client.",
			},
			"client_id": {
				Type:        schema.TypeString,
				Description: "The Client ID from Vault.",
				Computed:    true,
			},
			"client_secret": {
				Type:        schema.TypeString,
				Description: "The Client Secret from Vault.",
				Computed:    true,
				Sensitive:   true,
			},
		},
	}
}

func readOIDCClientCredsResource(d *schema.ResourceData, meta interface{}) error {
	client, e := GetClient(d, meta)
	if e != nil {
		return e
	}
	name := d.Get("name").(string)
	path := getOIDCClientPath(name)

	creds, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault, err=%w", err)
	}

	log.Printf("[DEBUG] Read %q from Vault", path)

	if creds == nil {
		return fmt.Errorf("no client found at %q", path)
	}

	clientId := creds.Data["client_id"].(string)

	if clientId == "" {
		return fmt.Errorf("client_id is not set in response")
	}

	clientSecret := creds.Data["client_secret"].(string)
	if clientSecret == "" {
		return fmt.Errorf("client_secret is not set in response")
	}

	d.SetId(path)

	if err := d.Set("client_id", clientId); err != nil {
		return err
	}

	if err := d.Set("client_secret", clientSecret); err != nil {
		return err
	}

	return nil
}
