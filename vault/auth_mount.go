// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
	"github.com/hashicorp/vault/api"
	"log"
)

const (
	fieldLockoutThreshold            = "lockout_threshold"
	fieldLockoutDuration             = "lockout_duration"
	fieldLockoutCounterResetDuration = "lockout_counter_reset_duration"
	fieldLockoutDisable              = "lockout_disable"
)

func authMountTuneSchema() *schema.Schema {
	return &schema.Schema{
		Deprecated: `Deprecated. Please use dedicated schema fields instead. Will be removed in next major release`,
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

type createMountRequestParams struct {
	Path      string
	MountType string

	// some auth engines manage the token type separately
	SkipTokenType bool
}

func getAuthMountSchema(excludes ...string) schemaMap {
	s := schemaMap{
		consts.FieldTokenType: {
			Type:         schema.TypeString,
			Optional:     true,
			Computed:     true,
			Description:  "Specifies the type of tokens that should be returned by the mount.",
			ValidateFunc: validation.StringInSlice([]string{"default-service", "default-batch", "service", "batch"}, false),
		},
		consts.FieldUserLockoutConfig: {
			Type:        schema.TypeMap,
			Optional:    true,
			Description: "Specifies the user lockout configuration for the mount. Requires Vault 1.13+.",
		},
	}

	for k, v := range getMountSchema(
		// not used by auth engines
		consts.FieldDelegatedAuthAccessors,
		consts.FieldExternalEntropyAccess,
		consts.FieldAllowedManagedKeys,
		consts.FieldOptions,
	) {
		s[k] = v
	}

	for _, v := range excludes {
		delete(s, v)
	}
	return s
}

func createAuthMount(ctx context.Context, d *schema.ResourceData, meta interface{}, client *api.Client, params *createMountRequestParams) error {
	options := &api.EnableAuthOptions{
		Type:        params.MountType,
		Description: d.Get(consts.FieldDescription).(string),
		Local:       d.Get(consts.FieldLocal).(bool),
		SealWrap:    d.Get(consts.FieldSealWrap).(bool),
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get(consts.FieldDefaultLeaseTTL)),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get(consts.FieldMaxLeaseTTL)),
		},
	}

	if v, ok := d.GetOk(consts.FieldAuditNonHMACRequestKeys); ok {
		options.Config.AuditNonHMACRequestKeys = expandStringSlice(v.([]interface{}))
	}
	if v, ok := d.GetOk(consts.FieldAuditNonHMACResponseKeys); ok {
		options.Config.AuditNonHMACResponseKeys = expandStringSlice(v.([]interface{}))
	}

	if v, ok := d.GetOk(consts.FieldPassthroughRequestHeaders); ok {
		options.Config.PassthroughRequestHeaders = expandStringSlice(v.([]interface{}))
	}

	if v, ok := d.GetOk(consts.FieldAllowedResponseHeaders); ok {
		options.Config.AllowedResponseHeaders = expandStringSlice(v.([]interface{}))
	}

	if v, ok := d.GetOk(consts.FieldListingVisibility); ok {
		options.Config.ListingVisibility = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldPluginVersion); ok {
		options.Config.PluginVersion = v.(string)
	}

	if !params.SkipTokenType {
		if v, ok := d.GetOk(consts.FieldTokenType); ok {
			options.Config.TokenType = v.(string)
		}
	}

	useAPIVer116Ent := provider.IsAPISupported(meta, provider.VaultVersion116) && provider.IsEnterpriseSupported(meta)
	if useAPIVer116Ent {
		if d.HasChange(consts.FieldIdentityTokenKey) {
			options.Config.IdentityTokenKey = d.Get(consts.FieldIdentityTokenKey).(string)
		}
	}

	log.Printf("[DEBUG] Creating auth mount %s in Vault", params.Path)

	err := client.Sys().EnableAuthWithOptionsWithContext(ctx, params.Path, options)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	return nil
}

func updateAuthMount(ctx context.Context, d *schema.ResourceData, meta interface{}, excludeType bool, skipTokenType bool) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	config := api.MountConfigInput{
		DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get(consts.FieldDefaultLeaseTTL)),
		MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get(consts.FieldMaxLeaseTTL)),
	}

	if d.HasChange(consts.FieldAuditNonHMACRequestKeys) {
		config.AuditNonHMACRequestKeys = expandStringSlice(d.Get(consts.FieldAuditNonHMACRequestKeys).([]interface{}))
	}

	if d.HasChange(consts.FieldAuditNonHMACResponseKeys) {
		config.AuditNonHMACResponseKeys = expandStringSlice(d.Get(consts.FieldAuditNonHMACResponseKeys).([]interface{}))
	}

	if d.HasChange(consts.FieldDescription) {
		description := fmt.Sprintf("%s", d.Get(consts.FieldDescription))
		config.Description = &description
	}

	path := d.Id()
	authPath := "auth/" + path

	if d.HasChange(consts.FieldPassthroughRequestHeaders) {
		config.PassthroughRequestHeaders = expandStringSlice(d.Get(consts.FieldPassthroughRequestHeaders).([]interface{}))
	}

	if d.HasChange(consts.FieldAllowedResponseHeaders) {
		config.AllowedResponseHeaders = expandStringSlice(d.Get(consts.FieldAllowedResponseHeaders).([]interface{}))
	}

	if d.HasChange(consts.FieldListingVisibility) {
		config.ListingVisibility = d.Get(consts.FieldListingVisibility).(string)
	}

	if d.HasChange(consts.FieldPluginVersion) {
		config.PluginVersion = d.Get(consts.FieldPluginVersion).(string)
	}

	if !skipTokenType {
		if d.HasChange(consts.FieldTokenType) {
			config.TokenType = d.Get(consts.FieldTokenType).(string)
		}
	}

	if d.HasChange(consts.FieldUserLockoutConfig) {
		userLockoutCfg, err := getUserLockoutConfig(d.Get(consts.FieldUserLockoutConfig).(map[string]interface{}))
		if err != nil {
			return fmt.Errorf("error reading '%s': %s", consts.FieldUserLockoutConfig, err)
		}

		config.UserLockoutConfig = userLockoutCfg
	}

	useAPIVer116Ent := provider.IsAPISupported(meta, provider.VaultVersion116) && provider.IsEnterpriseSupported(meta)
	if useAPIVer116Ent {
		if d.HasChange(consts.FieldIdentityTokenKey) {
			config.IdentityTokenKey = d.Get(consts.FieldIdentityTokenKey).(string)
		}
	}

	log.Printf("[DEBUG] Updating auth mount %s in Vault", path)

	if err := client.Sys().TuneMountWithContext(ctx, authPath, config); err != nil {
		return fmt.Errorf("error updating Vault: %s", err)
	}

	return readAuthMount(ctx, d, meta, excludeType, skipTokenType)
}

func readAuthMount(ctx context.Context, d *schema.ResourceData, meta interface{}, excludeType bool, skipTokenType bool) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading auth mount %s from Vault", path)

	mount, err := mountutil.GetAuthMount(ctx, client, path)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found, removing from state.", path)
			d.SetId("")
			return nil
		}
		return err
	}

	if !excludeType {
		if err := d.Set(consts.FieldType, mount.Type); err != nil {
			return err
		}
	}

	if err := d.Set(consts.FieldPath, path); err != nil {
		return err
	}
	if err := d.Set(consts.FieldDescription, mount.Description); err != nil {
		return err
	}
	if err := d.Set(consts.FieldDefaultLeaseTTL, mount.Config.DefaultLeaseTTL); err != nil {
		return err
	}
	if err := d.Set(consts.FieldMaxLeaseTTL, mount.Config.MaxLeaseTTL); err != nil {
		return err
	}
	if err := d.Set(consts.FieldAuditNonHMACRequestKeys, mount.Config.AuditNonHMACRequestKeys); err != nil {
		return err
	}
	if err := d.Set(consts.FieldAuditNonHMACResponseKeys, mount.Config.AuditNonHMACResponseKeys); err != nil {
		return err
	}
	if err := d.Set(consts.FieldAccessor, mount.Accessor); err != nil {
		return err
	}
	if err := d.Set(consts.FieldLocal, mount.Local); err != nil {
		return err
	}
	if err := d.Set(consts.FieldSealWrap, mount.SealWrap); err != nil {
		return err
	}

	if err := d.Set(consts.FieldPassthroughRequestHeaders, mount.Config.PassthroughRequestHeaders); err != nil {
		return err
	}
	if err := d.Set(consts.FieldAllowedResponseHeaders, mount.Config.AllowedResponseHeaders); err != nil {
		return err
	}

	if err := d.Set(consts.FieldListingVisibility, mount.Config.ListingVisibility); err != nil {
		return err
	}
	if err := d.Set(consts.FieldIdentityTokenKey, mount.Config.IdentityTokenKey); err != nil {
		return err
	}

	if !skipTokenType {
		if err := d.Set(consts.FieldTokenType, mount.Config.TokenType); err != nil {
			return err
		}
	}

	// TODO uncomment after fixing bug in vault/api package — user_lockout_config can not be read
	//if err := d.Set(consts.FieldUserLockoutConfig, flattenUserLockoutConfig(mount.Config.UserLockoutConfig)); err != nil {
	//	return err
	//}

	return nil
}

func getUserLockoutConfig(m map[string]interface{}) (*api.UserLockoutConfigInput, error) {
	result := &api.UserLockoutConfigInput{}

	if v, ok := m[fieldLockoutDuration]; ok && v != nil {
		result.LockoutDuration = v.(string)
	}

	if v, ok := m[fieldLockoutCounterResetDuration]; ok && v != nil {
		result.LockoutCounterResetDuration = v.(string)
	}

	if v, ok := m[fieldLockoutThreshold]; ok && v != nil {
		result.LockoutThreshold = v.(string)
	}

	if v, ok := m[fieldLockoutDisable]; ok && v != nil {
		result.DisableLockout = v.(*bool)
	}

	return result, nil
}

func flattenUserLockoutConfig(output *api.UserLockoutConfigOutput) map[string]string {
	m := make(map[string]string)

	if output != nil {
		m[fieldLockoutThreshold] = fmt.Sprintf("%d", output.LockoutThreshold)
		m[fieldLockoutDisable] = fmt.Sprintf("%t", *output.DisableLockout)
		m[fieldLockoutDuration] = fmt.Sprintf("%d", output.LockoutDuration)
		m[fieldLockoutCounterResetDuration] = fmt.Sprintf("%d", output.LockoutCounterReset)
	}

	return m
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
