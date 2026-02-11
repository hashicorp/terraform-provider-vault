// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"maps"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func authMountTuneSchema() *schema.Schema {
	return &schema.Schema{
		Type:       schema.TypeList,
		Optional:   true,
		Computed:   true,
		MaxItems:   1,
		ConfigMode: schema.SchemaConfigModeAttr,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				consts.FieldDefaultLeaseTTL: {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies the default time-to-live duration. This overrides the global default. A value of 0 is equivalent to the system default TTL",
					ValidateFunc: provider.ValidateDuration,
				},
				consts.FieldMaxLeaseTTL: {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies the maximum time-to-live duration. This overrides the global default. A value of 0 are equivalent and set to the system max TTL.",
					ValidateFunc: provider.ValidateDuration,
				},
				consts.FieldAuditNonHMACRequestKeys: {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the request data object.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				consts.FieldAuditNonHMACResponseKeys: {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the response data object.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				consts.FieldListingVisibility: {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies whether to show this mount in the UI-specific listing endpoint. Valid values are \"unauth\" or \"hidden\". If not set, behaves like \"hidden\".",
					ValidateFunc: validation.StringInSlice([]string{"unauth", "hidden"}, false),
				},
				consts.FieldPassthroughRequestHeaders: {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "List of headers to whitelist and pass from the request to the backend.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				consts.FieldAllowedResponseHeaders: {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "List of headers to whitelist and allowing a plugin to include them in the response.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				consts.FieldTokenType: {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies the type of tokens that should be returned by the mount.",
					ValidateFunc: validation.StringInSlice([]string{"default-service", "default-batch", "service", "batch"}, false),
				},
			},
		},
	}
}

// authExternalPluginMountTuneSchema extends authMountTuneSchema with
// fields that support external plugins.
func authExternalPluginMountTuneSchema() *schema.Schema {
	m := map[string]*schema.Schema{
		consts.FieldPluginVersion: {
			// plugin_version is only allowed under resource_auth_backend
			// as it's the only way to enable external plugins via specifying
			// the plugin type (aka the plugin name).
			// There is no support currently for specifying the plugin name/type under
			// auth specific backend resources (e.g. vault_github_auth_backend)
			Type:     schema.TypeString,
			Optional: true,
			Description: `Specifies the semantic version of the external plugin  
to use. e.g. 'v1.0.0'. If not specified, the server will select any matching 
unversioned plugin that may have been registered, the latest versioned plugin 
registered, or a built-in plugin in that order of precedence.`,
		},
		consts.FieldOverridePinnedVersion: {
			Type:     schema.TypeBool,
			Optional: true,
			Description: `(Enterprise only). Specifies whether to override 
the pinned version using plugin_version.`,
		},
	}
	s := authMountTuneSchema()

	re := s.Elem.(*schema.Resource)
	maps.Copy(re.Schema, m)

	return s
}

func authMountTune(ctx context.Context, client *api.Client, path string, configured interface{}) error {
	configuredList, ok := configured.([]interface{})
	if !ok {
		return fmt.Errorf("error type asserting tune block: expected []interface{}, got %T", configured)
	}

	input, err := expandAuthMethodTune(configuredList)
	if err != nil {
		return fmt.Errorf("error expanding tune block %q: %s", path, err)
	}

	return tuneMount(ctx, client, path, input)
}

func tuneMount(ctx context.Context, client *api.Client, path string, input api.MountConfigInput) error {
	err := client.Sys().TuneMountWithContext(ctx, path, input)
	if err != nil {
		return err
	}
	return nil
}

func authMountTuneGet(ctx context.Context, client *api.Client, path string) (map[string]interface{}, error) {
	tune, err := client.Sys().MountConfigWithContext(ctx, path)
	if err != nil {
		log.Printf("[ERROR] Error when reading tune config from path %q: %s", path+"/tune", err)
		return nil, err
	}

	return flattenAuthMethodTune(tune), nil
}

func authMountDisable(ctx context.Context, client *api.Client, path string) diag.Diagnostics {
	log.Printf("[DEBUG] Disabling auth mount config from '%q'", path)
	err := client.Sys().DisableAuthWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error disabling auth mount from '%q': %s", path, err)
	}
	log.Printf("[INFO] Disabled auth mount from '%q'", path)

	return nil
}
