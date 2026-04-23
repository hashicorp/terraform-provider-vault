// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func jwtAuthBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
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

			consts.FieldType: {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Description:  "Type of backend. Can be either 'jwt' or 'oidc'",
				Default:      "jwt",
				ValidateFunc: validation.StringInSlice([]string{"jwt", "oidc"}, false),
			},

			consts.FieldDescription: {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			consts.FieldOIDCDiscoveryURL: {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{consts.FieldJWKSURL, consts.FieldJWTValidationPubkeys},
				Description:   "The OIDC Discovery URL, without any .well-known component (base path). Cannot be used with 'jwks_url' or 'jwt_validation_pubkeys'.",
			},

			consts.FieldOIDCDiscoveryCAPEM: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used",
			},

			consts.FieldOIDCClientID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client ID used for OIDC",
			},
			consts.FieldOIDCClientSecret: {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				Description:   "Client Secret used for OIDC",
				ConflictsWith: []string{consts.FieldOIDCClientSecretWO},
			},

			consts.FieldOIDCClientSecretWO: {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				WriteOnly:     true,
				Description:   "Write-only Client Secret used for OIDC. This field is recommended over oidc_client_secret for enhanced security.",
				ConflictsWith: []string{"oidc_client_secret"},
			},

			consts.FieldOIDCClientSecretWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Version counter for write-only oidc_client_secret field. Increment this value to force update of the secret.",
				RequiredWith: []string{consts.FieldOIDCClientSecretWO},
			},

			consts.FieldOIDCResponseMode: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The response mode to be used in the OAuth2 request. Allowed values are 'query' and 'form_post'. Defaults to 'query'. If using Vault namespaces, and oidc_response_mode is 'form_post', then 'namespace_in_state' should be set to false.",
			},

			consts.FieldOIDCResponseTypes: {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "The response types to request. Allowed values are 'code' and 'id_token'. Defaults to 'code'. Note: 'id_token' may only be used if 'oidc_response_mode' is set to 'form_post'.",
			},

			consts.FieldJWKSURL: {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{consts.FieldOIDCDiscoveryURL, consts.FieldJWTValidationPubkeys},
				Description:   "JWKS URL to use to authenticate signatures. Cannot be used with 'oidc_discovery_url' or 'jwt_validation_pubkeys'.",
			},

			consts.FieldJWKSCAPEM: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate connections to the JWKS URL. If not set, system certificates are used.",
			},

			consts.FieldJWKSPairs: {
				Type:          schema.TypeList,
				Elem:          &schema.Schema{Type: schema.TypeMap},
				Optional:      true,
				ConflictsWith: []string{consts.FieldJWKSURL, consts.FieldJWKSCAPEM},
				Description:   "List of JWKS URL and optional CA certificate pairs. Cannot be used with 'jwks_url' or 'jwks_ca_pem'. Requires Vault 1.16+.",
			},

			consts.FieldJWTValidationPubkeys: {
				Type:          schema.TypeList,
				Elem:          &schema.Schema{Type: schema.TypeString},
				Optional:      true,
				ConflictsWith: []string{consts.FieldJWKSURL, consts.FieldOIDCDiscoveryURL},
				Description:   "A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used with 'jwks_url' or 'oidc_discovery_url'. ",
			},

			consts.FieldBoundIssuer: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value against which to match the iss claim in a JWT",
			},

			consts.FieldJWTSupportedAlgs: {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "A list of supported signing algorithms. Defaults to [RS256]",
			},

			consts.FieldDefaultRole: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The default role to use if none is provided during login",
			},

			consts.FieldAccessor: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the JWT auth backend",
			},

			consts.FieldLocal: {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Default:     false,
				Description: "Specifies if the auth method is local only",
			},

			consts.FieldProviderConfig: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Provider specific handling configuration",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			consts.FieldNamespaceInState: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Pass namespace in the OIDC state parameter instead of as a separate query parameter. With this setting, the allowed redirect URL(s) in Vault and on the provider side should not contain a namespace query parameter. This means only one redirect URL entry needs to be maintained on the OIDC provider side for all vault namespaces that will be authenticating against it. Defaults to true for new configs.",
			},

			"tune": authMountTuneSchema(),
		},
	}, false)
}

func jwtCustomizeDiff(ctx context.Context, d *schema.ResourceDiff, meta interface{}) error {
	attributes := []string{
		consts.FieldOIDCDiscoveryURL,
		consts.FieldJWKSURL,
		consts.FieldJWTValidationPubkeys,
		consts.FieldProviderConfig,
		consts.FieldJWKSPairs,
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

	return errors.New("exactly one of oidc_discovery_url, jwks_url, jwks_pairs, or jwt_validation_pubkeys should be provided")
}

// TODO: build this from the Resource Schema?
var matchingJwtMountConfigOptions = []string{
	consts.FieldOIDCDiscoveryURL,
	consts.FieldOIDCDiscoveryCAPEM,
	consts.FieldOIDCClientID,
	consts.FieldOIDCClientSecret,
	consts.FieldOIDCResponseMode,
	consts.FieldOIDCResponseTypes,
	consts.FieldJWKSURL,
	consts.FieldJWKSCAPEM,
	consts.FieldJWKSPairs,
	consts.FieldJWTValidationPubkeys,
	consts.FieldBoundIssuer,
	consts.FieldJWTSupportedAlgs,
	consts.FieldDefaultRole,
	consts.FieldProviderConfig,
	consts.FieldNamespaceInState,
}

func jwtAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	authType := d.Get(consts.FieldType).(string)
	path := getJwtPath(d)
	options := &api.EnableAuthOptions{
		Type:        authType,
		Description: d.Get(consts.FieldDescription).(string),
		Local:       d.Get(consts.FieldLocal).(bool),
	}

	log.Printf("[DEBUG] Writing auth %s to Vault", authType)

	err := client.Sys().EnableAuthWithOptionsWithContext(ctx, path, options)
	if err != nil {
		return diag.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return jwtAuthBackendUpdate(ctx, d, meta)
}

func jwtAuthBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := getJwtPath(d)

	log.Printf("[DEBUG] Deleting auth %s from Vault", path)

	err := client.Sys().DisableAuthWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error disabling auth from Vault: %s", err)
	}

	return nil
}

func jwtAuthBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	useAPIVer116 := provider.IsAPISupported(meta, provider.VaultVersion116)

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
	d.Set(consts.FieldPath, path)

	mount, err := mountutil.GetAuthMount(ctx, client, path)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found, removing from state.", path)
			d.SetId("")
			return nil
		}
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

	d.Set(consts.FieldType, mount.Type)
	d.Set(consts.FieldLocal, mount.Local)

	d.Set(consts.FieldAccessor, mount.Accessor)
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
		if configOption == consts.FieldOIDCClientSecret {
			continue
		}

		if configOption == consts.FieldJWKSPairs && !useAPIVer116 {
			continue
		}

		// Normalize provider_config values from Vault API (bool/int) to strings
		// to match the Terraform schema definition and prevent drift
		if configOption == consts.FieldProviderConfig {
			normalized := normalizeProviderConfigFromVault(config.Data[configOption])
			d.Set(configOption, normalized)
		} else {
			d.Set(configOption, config.Data[configOption])
		}
	}

	log.Printf("[DEBUG] Reading jwt auth tune from %q", path+"/tune")
	rawTune, err := authMountTuneGet(ctx, client, "auth/"+path)
	if err != nil {
		return diag.Errorf("error reading tune information from Vault: %s", err)
	}

	input, err := retrieveMountConfigInput(d)
	if err != nil {
		return diag.Errorf("error retrieving tune configuration from state: %s", err)
	}

	mergedTune := mergeAuthMethodTune(rawTune, input)

	if err := d.Set("tune", mergedTune); err != nil {
		log.Printf("[ERROR] Error when setting tune config from path %q to state: %s", path+"/tune", err)
		return diag.FromErr(err)
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

func normalizeProviderConfigFromVault(input interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}

	inputMap, ok := input.(map[string]interface{})
	if !ok {
		return nil
	}

	normalized := make(map[string]interface{})
	for k, v := range inputMap {
		switch k {
		case "fetch_groups", "fetch_user_info":
			// Convert bool to string
			if boolVal, ok := v.(bool); ok {
				normalized[k] = strconv.FormatBool(boolVal)
			} else {
				normalized[k] = fmt.Sprintf("%v", v)
			}
		case "groups_recurse_max_depth":
			// Convert int to string
			switch val := v.(type) {
			case int:
				normalized[k] = strconv.Itoa(val)
			case int64:
				normalized[k] = strconv.FormatInt(val, 10)
			case float64:
				// JSON numbers are float64
				normalized[k] = strconv.FormatInt(int64(val), 10)
			default:
				normalized[k] = fmt.Sprintf("%v", v)
			}
		default:
			// Keep strings as-is
			if strVal, ok := v.(string); ok {
				normalized[k] = strVal
			} else {
				normalized[k] = fmt.Sprintf("%v", v)
			}
		}
	}
	return normalized
}

func jwtAuthBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	useAPIVer116 := provider.IsAPISupported(meta, provider.VaultVersion116)

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
	}

	configuration := map[string]interface{}{}
	for _, configOption := range matchingJwtMountConfigOptions {
		if _, ok := d.GetOkExists(configOption); ok || d.HasChange(configOption) {
			switch configOption {
			case consts.FieldJWKSPairs:
				if useAPIVer116 {
					configuration[configOption] = d.Get(configOption)
				} else {
					log.Printf("[WARN] Skipping jwt auth %q update for %q, requires Vault 1.16+", configOption, path)
				}
			case consts.FieldProviderConfig:
				newConfig, err := convertProviderConfigValues(d.Get(configOption).(map[string]interface{}))
				if err != nil {
					return diag.FromErr(err)
				}
				configuration[configOption] = newConfig
			case consts.FieldOIDCClientSecret:
				// Handle legacy oidc_client_secret field
				if v, ok := d.GetOk(consts.FieldOIDCClientSecret); ok && v != nil {
					configuration[consts.FieldOIDCClientSecret] = v.(string)
				}
			default:
				configuration[configOption] = d.Get(configOption)
			}
		}
	}

	// Handle write-only oidc_client_secret field.
	// Vault's OIDC config requires oidc_client_secret to be sent
	// on every write operation when type="oidc". We send the secret whenever the
	// write-only version field is set, regardless of whether it changed.
	if _, ok := d.GetOk(consts.FieldOIDCClientSecretWOVersion); ok {
		p := cty.GetAttrPath(consts.FieldOIDCClientSecretWO)
		woVal, _ := d.GetRawConfigAt(p)
		if !woVal.IsNull() {
			configuration[consts.FieldOIDCClientSecret] = woVal.AsString()
		}
	}

	_, err := client.Logical().WriteWithContext(ctx, jwtConfigEndpoint(path), configuration)
	if err != nil {
		return diag.Errorf("error updating configuration to Vault for path %s: %s", path, err)
	}

	if d.HasChange(consts.FieldTune) {
		log.Printf("[DEBUG] JWT/OIDC Auth '%q' tune configuration changed", d.Id())
		if raw, ok := d.GetOk(consts.FieldTune); ok {
			backendType := d.Get(consts.FieldType)
			log.Printf("[DEBUG] Writing %s auth tune to '%q'", backendType, path)

			err := authMountTune(ctx, client, "auth/"+path, raw)
			if err != nil {
				return diag.FromErr(err)
			}

			log.Printf("[DEBUG] Written %s auth tune to %q", backendType, path)
		}
	}

	return jwtAuthBackendRead(ctx, d, meta)
}

func jwtConfigEndpoint(path string) string {
	return fmt.Sprintf("/auth/%s/config", path)
}

func getJwtPath(d *schema.ResourceData) string {
	return d.Get("path").(string)
}
