// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var tuneFieldsMapping = map[string]string{
	"default_lease_ttl":            "DefaultLeaseTTL",
	"max_lease_ttl":                "MaxLeaseTTL",
	"listing_visibility":           "ListingVisibility",
	"token_type":                   "TokenType",
	"plugin_version":               "PluginVersion",
	"audit_non_hmac_request_keys":  "AuditNonHMACRequestKeys",
	"audit_non_hmac_response_keys": "AuditNonHMACResponseKeys",
	"passthrough_request_headers":  "PassthroughRequestHeaders",
	"allowed_response_headers":     "AllowedResponseHeaders",
	"user_lockout_config":          "UserLockoutConfig",
}

func authTuneResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		SchemaVersion: 1,

		Create: authTuneWrite,
		Delete: authTuneDelete,
		Read:   provider.ReadWrapper(authTuneRead),
		Update: authTuneUpdate,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),

		Schema: map[string]*schema.Schema{

			consts.FieldPath: {
				Type:         schema.TypeString,
				Required:     true,
				Computed:     false,
				Description:  "path of auth mount to tune.",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},
			"default_lease_ttl": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  "Specifies the default time-to-live duration. This overrides the global default. A value of 0 is equivalent to the system default TTL",
				ValidateFunc: provider.ValidateDuration,
			},
			"max_lease_ttl": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  "Specifies the maximum time-to-live duration. This overrides the global default. A value of 0 are equivalent and set to the system max TTL.",
				ValidateFunc: provider.ValidateDuration,
			},
			"audit_non_hmac_request_keys": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the request data object.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"audit_non_hmac_response_keys": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the response data object.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"listing_visibility": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  "Specifies whether to show this mount in the UI-specific listing endpoint. Valid values are \"unauth\" or \"hidden\". If not set, behaves like \"hidden\".",
				ValidateFunc: validation.StringInSlice([]string{"unauth", "hidden"}, false),
			},
			"passthrough_request_headers": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "List of headers to whitelist and pass from the request to the backend.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"allowed_response_headers": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "List of headers to whitelist and allowing a plugin to include them in the response.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"token_type": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  "Specifies the type of tokens that should be returned by the mount.",
				ValidateFunc: validation.StringInSlice([]string{"default-service", "default-batch", "service", "batch"}, false),
			},
			"plugin_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the semantic version of the plugin to use, e.g. \"v1.0.0\". Changes will not take effect until the mount is reloaded.",
			},
			"user_lockout_config": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Specifies the user lockout configuration for the mount. User lockout feature was added in Vault 1.13.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"lockout_threshold": {
							Description: "Specifies the number of failed login attempts after which the user is locked out, specified as a string like \"15\".",
							Optional:    true,
							Type:        schema.TypeString,
						},
						"lockout_duration": {
							Description:  "Specifies the duration for which an user will be locked out, specified as a string duration like \"5s\" or \"30m\".",
							Optional:     true,
							Type:         schema.TypeString,
							ValidateFunc: provider.ValidateDuration,
						},
						"lockout_counter_reset": {
							Description:  "Specifies the duration after which the lockout counter is reset with no failed login attempts, specified as a string duration like \"5s\" or \"30m\".",
							Optional:     true,
							Type:         schema.TypeString,
							ValidateFunc: provider.ValidateDuration,
						},
						"lockout_disable": {
							Description: "Disables the user lockout feature for this mount if set to true. Defaults to false.",
							Optional:    true,
							Type:        schema.TypeBool,
						},
					},
				},
			},
		},
	}, false)
}

func createBoolPointer(s string) *bool {
	boolValue, err := strconv.ParseBool(s)
	if err != nil {
		log.Fatal(err)
	}

	return &boolValue
}

func setUserLockoutConfig(d *schema.ResourceData, meta interface{}, inputData interface{}, client *api.Client, path string) (api.UserLockoutConfigInput, error) {
	var lockoutConfig api.UserLockoutConfigInput

	mount, err := getAuthMountIfPresent(client, path)
	if err != nil {
		return lockoutConfig, err
	}
	for _, supportedMount := range []string{"ldap", "approle", "userpass"} {
		log.Printf("[DEBUG] Verifying lockout supported for mount of type %s", mount.Type)
		if supportedMount == mount.Type {
			log.Printf("[DEBUG] Lockout supported for mount of type %s", mount.Type)
			lockoutInt := inputData.(*schema.Set).List()
			for _, lockoutDetail := range lockoutInt {
				for key, value := range lockoutDetail.(map[string]interface{}) {
					switch key {
					case "lockout_threshold":
						if value != nil && value != "" {
							lockoutConfig.LockoutThreshold = fmt.Sprintf("%s", value)
						} else {
							lockoutConfig.LockoutThreshold = "0"
						}
					case "lockout_duration":
						if value != nil && value != "" {
							lockoutConfig.LockoutDuration = fmt.Sprintf("%s", value)
						} else {
							lockoutConfig.LockoutDuration = "0"
						}
					case "lockout_counter_reset":
						if value != nil && value != "" {
							lockoutConfig.LockoutCounterResetDuration = fmt.Sprintf("%s", value)
						} else {
							lockoutConfig.LockoutCounterResetDuration = "0"
						}
					case "lockout_disable":
						if value != nil && value != "" {
							boolPointer := createBoolPointer(fmt.Sprintf("%t", value))
							lockoutConfig.DisableLockout = boolPointer
						} else {
							boolPointer := createBoolPointer("false")
							lockoutConfig.DisableLockout = boolPointer
						}
					}
				}
			}
		} else {
			log.Printf("[DEBUG] Lockout not supported for mount of type %s", mount.Type)
		}
	}
	return lockoutConfig, nil
}

func authTuneWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get("path").(string)
	d.SetId(path)

	var config api.MountConfigInput

	for k, v := range tuneFieldsMapping {
		if inputData, ok := d.GetOk(k); ok {
			switch v {
			case "DefaultLeaseTTL":
				config.DefaultLeaseTTL = inputData.(string)
			case "MaxLeaseTTL":
				config.MaxLeaseTTL = inputData.(string)
			case "ListingVisibility":
				config.ListingVisibility = inputData.(string)
			case "TokenType":
				config.TokenType = inputData.(string)
			case "PluginVersion":
				config.PluginVersion = inputData.(string)
			case "AuditNonHMACRequestKeys":
				config.AuditNonHMACRequestKeys = expandStringSlice(inputData.([]interface{}))
			case "AuditNonHMACResponseKeys":
				config.AuditNonHMACResponseKeys = expandStringSlice(inputData.([]interface{}))
			case "PassthroughRequestHeaders":
				config.PassthroughRequestHeaders = expandStringSlice(inputData.([]interface{}))
			case "AllowedResponseHeaders":
				config.AllowedResponseHeaders = expandStringSlice(inputData.([]interface{}))
			case "UserLockoutConfig":
				lockoutConfig, err := setUserLockoutConfig(d, meta, inputData, client, path)
				if err != nil {
					return err
				}
				config.UserLockoutConfig = &lockoutConfig
			}
		}
	}

	err := client.Sys().TuneMount("auth/"+path, config)
	if err != nil {
		return err
	}

	return authTuneRead(d, meta)
}

func authTuneDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	var systemDefaultLeaseTTL int
	var systemMaxLeaseTTL int

	tokenMount, err := getAuthMountIfPresent(client, "token")
	if err == nil {
		systemDefaultLeaseTTL = tokenMount.Config.DefaultLeaseTTL
		systemMaxLeaseTTL = tokenMount.Config.MaxLeaseTTL
	} else {
		systemDefaultLeaseTTL = 2764800
		systemMaxLeaseTTL = 2764800
	}

	var lockoutResetDefaults api.UserLockoutConfigInput
	lockoutResetDefaults.LockoutThreshold = "0"
	lockoutResetDefaults.LockoutDuration = "0"
	lockoutResetDefaults.LockoutCounterResetDuration = "0"
	lockoutResetDefaults.DisableLockout = createBoolPointer("false")

	resetDefaults := api.MountConfigInput{
		DefaultLeaseTTL:           fmt.Sprint(systemDefaultLeaseTTL),
		MaxLeaseTTL:               fmt.Sprint(systemMaxLeaseTTL),
		AuditNonHMACRequestKeys:   []string{""},
		AuditNonHMACResponseKeys:  []string{""},
		ListingVisibility:         "hidden",
		PassthroughRequestHeaders: []string{""},
		AllowedResponseHeaders:    []string{""},
		TokenType:                 "default-service",
		PluginVersion:             "",
		UserLockoutConfig:         &lockoutResetDefaults,
	}

	log.Printf("[DEBUG] Deleting auth tuning %s from Vault", path)

	if err := tuneMount(client, "auth/"+path, resetDefaults); err != nil {
		return err
	}

	return nil
}

func authTuneRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	mount, err := getAuthMountIfPresent(client, path)
	if err != nil {
		return err
	}
	if mount == nil {
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Reading auth tune from %q", path+"/tune")
	rawTune, err := authMountTuneGet(client, "auth/"+path)
	if err != nil {
		return fmt.Errorf("error reading raw tune information from Vault: %s", err)
	}

	detailTune, err := client.Logical().Read("sys/auth/" + path + "/tune")
	if err != nil {
		return fmt.Errorf("error reading detailed tune information from Vault: %s", err)
	}

	userLockoutFields := []string{
		"user_lockout_threshold",
		"user_lockout_duration",
		"user_lockout_counter_reset_duration",
		"user_lockout_disable",
	}

	lockoutMap := make(map[string]interface{})
	for _, v := range userLockoutFields {
		if val, ok := detailTune.Data[v]; ok {
			lockoutMap[v] = val
		}
	}

	lockoutJson, err := json.Marshal(lockoutMap)
	if err != nil {
		return fmt.Errorf("error marshalling lockout configuration: %s", err)
	}

	var i interface{} = lockoutJson
	rawTune["user_lockout_config"] = i
	for k := range tuneFieldsMapping {
		d.Set(k, rawTune[k])
	}

	return nil
}

func authTuneUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Tuning auth %s in Vault", path)

	if !d.IsNewResource() {
		_, e = util.Remount(d, client, consts.FieldPath, true)
		if e != nil {
			return e
		}
	}

	var config api.MountConfigInput

	for k, v := range tuneFieldsMapping {
		if d.HasChange(k) {
			switch v {
			case "DefaultLeaseTTL":
				config.DefaultLeaseTTL = d.Get(k).(string)
			case "MaxLeaseTTL":
				config.MaxLeaseTTL = d.Get(k).(string)
			case "ListingVisibility":
				config.ListingVisibility = d.Get(k).(string)
			case "TokenType":
				config.TokenType = d.Get(k).(string)
			case "PluginVersion":
				config.PluginVersion = d.Get(k).(string)
			case "AuditNonHMACRequestKeys":
				config.AuditNonHMACRequestKeys = expandStringSlice(d.Get(k).([]interface{}))
			case "AuditNonHMACResponseKeys":
				config.AuditNonHMACResponseKeys = expandStringSlice(d.Get(k).([]interface{}))
			case "PassthroughRequestHeaders":
				config.PassthroughRequestHeaders = expandStringSlice(d.Get(k).([]interface{}))
			case "AllowedResponseHeaders":
				config.AllowedResponseHeaders = expandStringSlice(d.Get(k).([]interface{}))
			case "UserLockoutConfig":
				lockoutConfig, err := setUserLockoutConfig(d, meta, d.Get(k), client, path)
				if err != nil {
					return err
				}
				config.UserLockoutConfig = &lockoutConfig
			}
		}
	}

	err := client.Sys().TuneMount("auth/"+path, config)
	if err != nil {
		return err
	}

	return authTuneRead(d, meta)
}
