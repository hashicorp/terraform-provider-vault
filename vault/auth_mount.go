// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func authMountTuneSchema() *schema.Schema {
	return &schema.Schema{
		Type:       schema.TypeSet,
		Optional:   true,
		Computed:   true,
		MaxItems:   1,
		ConfigMode: schema.SchemaConfigModeAttr,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"default_lease_ttl": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies the default time-to-live duration. This overrides the global default. A value of 0 is equivalent to the system default TTL",
					ValidateFunc: provider.ValidateDuration,
				},
				"max_lease_ttl": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies the maximum time-to-live duration. This overrides the global default. A value of 0 are equivalent and set to the system max TTL.",
					ValidateFunc: provider.ValidateDuration,
				},
				"audit_non_hmac_request_keys": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the request data object.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"audit_non_hmac_response_keys": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the response data object.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"listing_visibility": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies whether to show this mount in the UI-specific listing endpoint. Valid values are \"unauth\" or \"hidden\". If not set, behaves like \"hidden\".",
					ValidateFunc: validation.StringInSlice([]string{"unauth", "hidden"}, false),
				},
				"passthrough_request_headers": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "List of headers to whitelist and pass from the request to the backend.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"allowed_response_headers": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "List of headers to whitelist and allowing a plugin to include them in the response.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"token_type": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies the type of tokens that should be returned by the mount.",
					ValidateFunc: validation.StringInSlice([]string{"default-service", "default-batch", "service", "batch"}, false),
				},
			},
		},
	}
}

func authMountInfoGet(client *api.Client, path string) (*api.AuthMount, error) {
	auths, err := client.Sys().ListAuth()
	if err != nil {
		return nil, fmt.Errorf("error reading from auth mounts: %s", err)
	}

	authMount := auths[strings.Trim(path, "/")+"/"]
	if authMount == nil {
		return nil, fmt.Errorf("auth mount %s not present", path)
	}
	return authMount, nil
}

func authMountTune(client *api.Client, path string, configured interface{}) error {
	input := expandAuthMethodTune(configured.(*schema.Set).List())

	return tuneMount(client, path, input)
}

func tuneMount(client *api.Client, path string, input api.MountConfigInput) error {
	err := client.Sys().TuneMount(path, input)
	if err != nil {
		return err
	}
	return nil
}

func authMountTuneGet(client *api.Client, path string) (map[string]interface{}, error) {
	tune, err := client.Sys().MountConfig(path)
	if err != nil {
		log.Printf("[ERROR] Error when reading tune config from path %q: %s", path+"/tune", err)
		return nil, err
	}

	return flattenAuthMethodTune(tune), nil
}

func authMountDisable(client *api.Client, path string) error {
	log.Printf("[DEBUG] Disabling auth mount config from '%q'", path)
	err := client.Sys().DisableAuth(path)
	if err != nil {
		return fmt.Errorf("error disabling auth mount from '%q': %s", path, err)
	}
	log.Printf("[INFO] Disabled auth mount from '%q'", path)

	return nil
}

// getAuthMountIfPresent will fetch the auth mount at the given path.
// Currently the Vault api package does not provide a GET /sys/mounts/:path
// method so we make a raw API request.
func getAuthMountIfPresent(client *api.Client, path string) (*api.AuthMount, error) {
	req := client.NewRequest(http.MethodGet, "/v1/sys/auth/"+path)
	resp, err := client.RawRequest(req)
	if err != nil {
		return nil, fmt.Errorf("error reading from Vault: %s", err)
	}

	if resp == nil {
		return nil, fmt.Errorf("expected a response, got nil response")
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %s", err)
	}
	var auth api.AuthMount
	err = json.Unmarshal(data, &auth)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal vault response: %s", err)
	}

	return &auth, nil
}
