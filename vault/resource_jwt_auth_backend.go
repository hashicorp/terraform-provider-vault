// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func jwtAuthBackendResource() *schema.Resource {
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CreateContext: jwtAuthBackendWrite,
		DeleteContext: jwtAuthBackendDelete,
		ReadContext:   provider.ReadContextWrapper(jwtAuthBackendRead),
		UpdateContext: jwtAuthBackendUpdate,

		CustomizeDiff: jwtCustomizeDiff,

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "path to mount the backend",
				Default:      "jwt",
				ValidateFunc: provider.ValidateNoTrailingSlash,
			},

			"type": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Description:  "Type of backend. Can be either 'jwt' or 'oidc'",
				Default:      "jwt",
				ValidateFunc: validation.StringInSlice([]string{"jwt", "oidc"}, false),
			},

			"description": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"oidc_discovery_url": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"jwks_url", "jwt_validation_pubkeys"},
				Description:   "The OIDC Discovery URL, without any .well-known component (base path). Cannot be used with 'jwks_url' or 'jwt_validation_pubkeys'.",
			},

			"oidc_discovery_ca_pem": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used",
			},

			"oidc_client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client ID used for OIDC",
			},

			"oidc_client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Client Secret used for OIDC",
			},

			"oidc_response_mode": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The response mode to be used in the OAuth2 request. Allowed values are 'query' and 'form_post'. Defaults to 'query'. If using Vault namespaces, and oidc_response_mode is 'form_post', then 'namespace_in_state' should be set to false.",
			},

			"oidc_response_types": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "The response types to request. Allowed values are 'code' and 'id_token'. Defaults to 'code'. Note: 'id_token' may only be used if 'oidc_response_mode' is set to 'form_post'.",
			},

			"jwks_url": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"oidc_discovery_url", "jwt_validation_pubkeys"},
				Description:   "JWKS URL to use to authenticate signatures. Cannot be used with 'oidc_discovery_url' or 'jwt_validation_pubkeys'.",
			},

			"jwks_ca_pem": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate connections to the JWKS URL. If not set, system certificates are used.",
			},

			"jwt_validation_pubkeys": {
				Type:          schema.TypeList,
				Elem:          &schema.Schema{Type: schema.TypeString},
				Optional:      true,
				ConflictsWith: []string{"jwks_url", "oidc_discovery_url"},
				Description:   "A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used with 'jwks_url' or 'oidc_discovery_url'. ",
			},

			"bound_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value against which to match the iss claim in a JWT",
			},

			"jwt_supported_algs": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "A list of supported signing algorithms. Defaults to [RS256]",
			},

			"default_role": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The default role to use if none is provided during login",
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the JWT auth backend",
			},

			"local": {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Default:     false,
				Description: "Specifies if the auth method is local only",
			},

			"provider_config": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Provider specific handling configuration",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			"namespace_in_state": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Pass namespace in the OIDC state parameter instead of as a separate query parameter. With this setting, the allowed redirect URL(s) in Vault and on the provider side should not contain a namespace query parameter. This means only one redirect URL entry needs to be maintained on the OIDC provider side for all vault namespaces that will be authenticating against it. Defaults to true for new configs.",
			},

			"tune": authMountTuneSchema(),
		},
	}, false)

	// Add common mount schema to the resource
	provider.MustAddSchema(r, getAuthMountSchema(
		consts.FieldPath,
		consts.FieldType,
		consts.FieldDescription,
		consts.FieldAccessor,
		consts.FieldLocal,
	))

	return r
}

func jwtCustomizeDiff(ctx context.Context, d *schema.ResourceDiff, meta interface{}) error {
	attributes := []string{
		"oidc_discovery_url",
		"jwks_url",
		"jwt_validation_pubkeys",
		"provider_config",
	}

	// to check whether mount migration is required
	f := getMountCustomizeDiffFunc(consts.FieldPath)

	for _, attr := range attributes {
		if !d.NewValueKnown(attr) {
			return f(ctx, d, meta)
		}

		if _, ok := d.GetOk(attr); ok {
			return f(ctx, d, meta)
		}
	}

	return errors.New("exactly one of oidc_discovery_url, jwks_url or jwt_validation_pubkeys should be provided")
}

// TODO: build this from the Resource Schema?
var matchingJwtMountConfigOptions = []string{
	"oidc_discovery_url",
	"oidc_discovery_ca_pem",
	"oidc_client_id",
	"oidc_client_secret",
	"oidc_response_mode",
	"oidc_response_types",
	"jwks_url",
	"jwks_ca_pem",
	"jwt_validation_pubkeys",
	"bound_issuer",
	"jwt_supported_algs",
	"default_role",
	"provider_config",
	"namespace_in_state",
}

func jwtAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := getJwtPath(d)

	if err := createAuthMount(ctx, d, meta, client, path, d.Get(consts.FieldType).(string)); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(path)

	return jwtAuthBackendUpdate(ctx, d, meta)
}

func jwtAuthBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	return authMountDisable(ctx, client, d.Id())
}

func jwtAuthBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := getJwtPath(d)
	log.Printf("[DEBUG] Reading auth %s from Vault", path)

	if path == "" {
		// In v2.11.0 and prior, path was not read and so not set in the state.
		// if path is empty here, we're likely in a import scenario where path is
		// empty. Because path is used as the ID in the resource, if path is empty
		// use the ID value
		path = d.Id()
	}

	if err := readAuthMount(ctx, d, meta, true); err != nil {
		return diag.FromErr(err)
	}

	config, err := client.Logical().ReadWithContext(ctx, jwtConfigEndpoint(path))
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}

	if config == nil {
		log.Printf("[WARN] JWT auth mount config %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	for _, configOption := range matchingJwtMountConfigOptions {
		// The oidc_client_secret is sensitive so it will not be in the response
		// Our options are to always assume it must be updated or always assume it
		//  matches our current state. This assumes it always matches our current
		//  state so that HasChange isn't always true and we store the last applied
		//  secret in the state file to know if the new secret should be applied.
		// This does intentionally miss the edge case where the oidc_client_secret
		//  is updated without Terraform. Since we cannot know the current state
		//  of the oidc_secret, Terraform will show no changes necessary even if
		//  the actual value in Vault does not match the value in state.
		if configOption == "oidc_client_secret" {
			continue
		}
		if err := d.Set(configOption, config.Data[configOption]); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func convertProviderConfigValues(input map[string]interface{}) (map[string]interface{}, error) {
	newConfig := make(map[string]interface{})
	for k, v := range input {
		val := v.(string)
		switch k {
		case "fetch_groups", "fetch_user_info":
			valBool, err := strconv.ParseBool(val)
			if err != nil {
				return nil, fmt.Errorf("could not convert %s to bool: %s", k, err)
			}
			newConfig[k] = valBool
		case "groups_recurse_max_depth":
			valInt, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("could not convert %s to int: %s", k, err)
			}
			newConfig[k] = valInt
		default:
			newConfig[k] = val
		}
	}
	return newConfig, nil
}

func jwtAuthBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := getJwtPath(d)
	log.Printf("[DEBUG] Updating auth %s in Vault", path)

	if !d.IsNewResource() {
		path, e = util.Remount(d, client, consts.FieldPath, true)
		if e != nil {
			return diag.FromErr(e)
		}

		// tune auth mount if needed
		if err := updateAuthMount(ctx, d, meta, true); err != nil {
			return diag.FromErr(err)
		}
	}

	configuration := map[string]interface{}{}
	for _, configOption := range matchingJwtMountConfigOptions {
		if _, ok := d.GetOkExists(configOption); ok || d.HasChange(configOption) {
			configuration[configOption] = d.Get(configOption)

			if configOption == "provider_config" {
				newConfig, err := convertProviderConfigValues(d.Get(configOption).(map[string]interface{}))
				if err != nil {
					return diag.FromErr(err)
				}

				configuration[configOption] = newConfig
			}
		}
	}

	_, err := client.Logical().WriteWithContext(ctx, jwtConfigEndpoint(path), configuration)
	if err != nil {
		return diag.Errorf("error updating configuration to Vault for path %s: %s", path, err)
	}

	return jwtAuthBackendRead(ctx, d, meta)
}

func jwtConfigEndpoint(path string) string {
	return fmt.Sprintf("/auth/%s/config", path)
}

func getJwtPath(d *schema.ResourceData) string {
	return d.Get("path").(string)
}
