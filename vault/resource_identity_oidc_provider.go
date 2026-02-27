// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const identityOIDCProviderPathPrefix = "identity/oidc/provider"

func identityOIDCProviderResource() *schema.Resource {
	return &schema.Resource{
		Create: identityOIDCProviderCreateUpdate,
		Update: identityOIDCProviderCreateUpdate,
		Read:   provider.ReadWrapper(identityOIDCProviderRead),
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
					"This value is computed using the issuer_host and https_enabled fields.",
				Computed: true,
			},
			"https_enabled": {
				Type:        schema.TypeBool,
				Description: "Set to true if the issuer endpoint uses HTTPS.",
				Default:     true,
				Optional:    true,
			},
			"issuer_host": {
				Type:        schema.TypeString,
				Description: "The host for the issuer. Can be either host or host:port.",
				Optional:    true,
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

func identityOIDCProviderConfigData(d *schema.ResourceData) map[string]interface{} {
	nonBooleanFields := []string{"issuer_host", "allowed_client_ids", "scopes_supported"}
	configData := map[string]interface{}{}

	if v, ok := d.GetOkExists("https_enabled"); ok {
		configData["https_enabled"] = v.(bool)
	}

	for _, k := range nonBooleanFields {
		if v, ok := d.GetOk(k); ok {
			if k == "allowed_client_ids" || k == "scopes_supported" {
				configData[k] = v.(*schema.Set).List()
				continue
			}
			configData[k] = v
		}
	}

	// Construct issuer URL if issuer_host provided
	if v, ok := configData["issuer_host"]; ok {
		scheme := "https"
		if !configData["https_enabled"].(bool) {
			scheme = "http"
		}

		configData["issuer"] = fmt.Sprintf("%s://%s", scheme, v.(string))
	}

	return configData
}

func getOIDCProviderPath(name string) string {
	return fmt.Sprintf("%s/%s", identityOIDCProviderPathPrefix, name)
}

func identityOIDCProviderCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	name := d.Get("name").(string)
	path := getOIDCProviderPath(name)

	configData := identityOIDCProviderConfigData(d)
	providerRequestData := map[string]interface{}{}

	providerAPIFields := []string{"issuer", "allowed_client_ids", "scopes_supported"}
	for _, k := range providerAPIFields {
		if v, ok := configData[k]; ok {
			providerRequestData[k] = v
		}
	}

	_, err := client.Logical().Write(path, providerRequestData)
	if err != nil {
		return fmt.Errorf("error writing OIDC Provider %s, err=%w", path, err)
	}

	log.Printf("[DEBUG] Wrote OIDC Provider to %s", path)

	d.SetId(path)

	return identityOIDCProviderRead(d, meta)
}

func identityOIDCProviderRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
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
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting OIDC Provider %s", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting OIDC Provider %q", path)
	}

	log.Printf("[DEBUG] Deleted OIDC Provider %q", path)

	return nil
}
