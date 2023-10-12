// Copyright (c) HashiCorp, Inc.
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

const identityOIDCOpenIDConfigPathSuffix = "/.well-known/openid-configuration"

func identityOIDCOpenIDConfigDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(readOIDCOpenIDConfigResource),
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the provider.",
			},
			"issuer": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The URL of the issuer for the provider.",
			},
			"jwks_uri": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The well known keys URI for the provider.",
			},
			"authorization_endpoint": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The Authorization Endpoint for the provider.",
			},
			"token_endpoint": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The Token Endpoint for the provider.",
			},
			"userinfo_endpoint": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The User Info Endpoint for the provider.",
			},
			"request_uri_parameter_supported": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Specifies whether Request URI Parameter is supported by the provider.",
			},
			"id_token_signing_alg_values_supported": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The signing algorithms supported by the provider.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"response_types_supported": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The response types supported by the provider.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"scopes_supported": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The scopes supported by the provider.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"subject_types_supported": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The subject types supported by the provider.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"grant_types_supported": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The grant types supported by the provider.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"token_endpoint_auth_methods_supported": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The token endpoint auth methods supported by the provider.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func readOIDCOpenIDConfigResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	name := d.Get("name").(string)
	path := "/v1/" + getOIDCProviderPath(name) + identityOIDCOpenIDConfigPathSuffix
	r := client.NewRequest("GET", path)

	log.Printf("[DEBUG] Reading %q from Vault", path)
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

	d.SetId(path)

	openIDConfigFields := []string{
		"issuer", "jwks_uri", "authorization_endpoint", "token_endpoint",
		"userinfo_endpoint", "request_uri_parameter_supported",
		"id_token_signing_alg_values_supported", "response_types_supported",
		"scopes_supported", "subject_types_supported", "grant_types_supported",
		"token_endpoint_auth_methods_supported",
	}

	for _, k := range openIDConfigFields {
		if err := d.Set(k, data[k]); err != nil {
			return fmt.Errorf("error setting state key %q on OpenID Config %q, err=%w", k, path, err)
		}
	}

	return nil
}
