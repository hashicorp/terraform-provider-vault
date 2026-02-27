// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const identityOIDCPublicKeysPathSuffix = "/.well-known/keys"

func identityOIDCPublicKeysDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(readOIDCPublicKeysResource),
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
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	name := d.Get("name").(string)
	path := "/v1/" + getOIDCProviderPath(name) + identityOIDCPublicKeysPathSuffix
	r := client.NewRequest("GET", path)

	resp, err := client.RawRequest(r)
	if err != nil {
		return fmt.Errorf("error performing GET at %s, err=%w", path, err)
	}

	if resp == nil {
		return fmt.Errorf("expected a response body, got nil response")
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return err
	}

	log.Printf("[DEBUG] Read %q from Vault", path)

	d.SetId(path)

	if err := d.Set("keys", data["keys"]); err != nil {
		return err
	}

	return nil
}
