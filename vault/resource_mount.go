// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

type schemaMap map[string]*schema.Schema

func getMountSchema(excludes ...string) schemaMap {
	s := schemaMap{
		consts.FieldPath: {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    false,
			Description: "Where the secret backend will be mounted",
		},
		consts.FieldType: {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Type of the backend, such as 'aws'",
		},
		consts.FieldDescription: {
			Type:        schema.TypeString,
			Optional:    true,
			Required:    false,
			Description: "Human-friendly description of the mount",
		},
		consts.FieldDefaultLeaseTTL: {
			Type:        schema.TypeInt,
			Required:    false,
			Optional:    true,
			Computed:    true,
			ForceNew:    false,
			Description: "Default lease duration for tokens and secrets in seconds",
		},

		consts.FieldMaxLeaseTTL: {
			Type:        schema.TypeInt,
			Required:    false,
			Optional:    true,
			Computed:    true,
			ForceNew:    false,
			Description: "Maximum possible lease duration for tokens and secrets in seconds",
		},

		consts.FieldAuditNonHMACRequestKeys: {
			Type:        schema.TypeList,
			Computed:    true,
			Optional:    true,
			Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the request data object.",
			Elem:        &schema.Schema{Type: schema.TypeString},
		},

		consts.FieldAuditNonHMACResponseKeys: {
			Type:        schema.TypeList,
			Computed:    true,
			Optional:    true,
			Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the response data object.",
			Elem:        &schema.Schema{Type: schema.TypeString},
		},

		consts.FieldAccessor: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Accessor of the mount",
		},

		consts.FieldLocal: {
			Type:        schema.TypeBool,
			Required:    false,
			Optional:    true,
			Computed:    false,
			ForceNew:    true,
			Description: "Local mount flag that can be explicitly set to true to enforce local mount in HA environment",
		},

		consts.FieldOptions: {
			Type:        schema.TypeMap,
			Required:    false,
			Optional:    true,
			Computed:    false,
			ForceNew:    false,
			Description: "Specifies mount type specific options that are passed to the backend",
		},

		consts.FieldSealWrap: {
			Type:        schema.TypeBool,
			Required:    false,
			Optional:    true,
			ForceNew:    true,
			Computed:    true,
			Description: "Enable seal wrapping for the mount, causing values stored by the mount to be wrapped by the seal's encryption capability",
		},

		consts.FieldExternalEntropyAccess: {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			ForceNew:    true,
			Description: "Enable the secrets engine to access Vault's external entropy source",
		},

		consts.FieldAllowedManagedKeys: {
			Type:        schema.TypeSet,
			Optional:    true,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Description: "List of managed key registry entry names that the mount in question is allowed to access",
		},

		consts.FieldListingVisibility: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Specifies whether to show this mount in the UI-specific listing endpoint",
		},

		consts.FieldPassthroughRequestHeaders: {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Description: "List of headers to allow and pass from the request to the plugin",
		},

		consts.FieldAllowedResponseHeaders: {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Description: "List of headers to allow and pass from the request to the plugin",
		},

		consts.FieldDelegatedAuthAccessors: {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Description: "List of headers to allow and pass from the request to the plugin",
		},

		consts.FieldPluginVersion: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Specifies the semantic version of the plugin to use, e.g. 'v1.0.0'",
		},

		consts.FieldIdentityTokenKey: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The key to use for signing plugin workload identity tokens",
		},
	}
	for _, v := range excludes {
		delete(s, v)
	}
	return s
}

func MountResource() *schema.Resource {
	return &schema.Resource{
		Create: mountWrite,
		Update: mountUpdate,
		Delete: mountDelete,
		Read:   provider.ReadWrapper(mountRead),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: getMountSchema(),
	}
}

func mountWrite(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Get(consts.FieldPath).(string)
	if err := createMount(d, client, path, d.Get(consts.FieldType).(string)); err != nil {
		return err
	}

	d.SetId(path)

	return mountRead(d, meta)
}

func createMount(d *schema.ResourceData, client *api.Client, path string, mountType string) error {
	fmt.Println("-- creating a mount")
	input := &api.MountInput{
		Type:        mountType,
		Description: d.Get(consts.FieldDescription).(string),
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get(consts.FieldDefaultLeaseTTL)),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get(consts.FieldMaxLeaseTTL)),
		},
		Local:                 d.Get(consts.FieldLocal).(bool),
		Options:               mountOptions(d),
		SealWrap:              d.Get(consts.FieldSealWrap).(bool),
		ExternalEntropyAccess: d.Get(consts.FieldExternalEntropyAccess).(bool),
	}

	if v, ok := d.GetOk(consts.FieldAuditNonHMACRequestKeys); ok {
		input.Config.AuditNonHMACRequestKeys = expandStringSlice(v.([]interface{}))
	}
	if v, ok := d.GetOk(consts.FieldAuditNonHMACResponseKeys); ok {
		input.Config.AuditNonHMACResponseKeys = expandStringSlice(v.([]interface{}))
	}

	if v, ok := d.GetOk(consts.FieldAllowedManagedKeys); ok {
		input.Config.AllowedManagedKeys = expandStringSlice(v.(*schema.Set).List())
	}

	if v, ok := d.GetOk(consts.FieldPassthroughRequestHeaders); ok {
		input.Config.PassthroughRequestHeaders = expandStringSlice(v.([]interface{}))
	}

	if v, ok := d.GetOk(consts.FieldAllowedResponseHeaders); ok {
		s := expandStringSlice(v.([]interface{}))
		input.Config.AllowedResponseHeaders = &s
	}

	if v, ok := d.GetOk(consts.FieldDelegatedAuthAccessors); ok {
		input.Config.DelegatedAuthAccessors = expandStringSlice(v.([]interface{}))
	}

	if v, ok := d.GetOk(consts.FieldListingVisibility); ok {
		input.Config.ListingVisibility = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldPluginVersion); ok {
		input.Config.PluginVersion = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldIdentityTokenKey); ok {
		input.Config.IdentityTokenKey = v.(string)
	}

	log.Printf("[DEBUG] Creating mount %s in Vault", path)

	if err := client.Sys().Mount(path, input); err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	return nil
}

func mountUpdate(d *schema.ResourceData, meta interface{}) error {
	return updateMount(d, meta, false)
}

func updateMount(d *schema.ResourceData, meta interface{}, excludeType bool) error {
	fmt.Println("-- updating a mount")
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	config := api.MountConfigInput{
		DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get(consts.FieldDefaultLeaseTTL)),
		MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get(consts.FieldMaxLeaseTTL)),
		Options:         mountOptions(d),
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

	if d.HasChange(consts.FieldPath) {
		newPath := d.Get(consts.FieldPath).(string)

		log.Printf("[DEBUG] Remount %s to %s in Vault", path, newPath)

		err := client.Sys().Remount(d.Id(), newPath)
		if err != nil {
			return fmt.Errorf("error remounting in Vault: %s", err)
		}

		d.SetId(newPath)
		path = newPath
	}

	if d.HasChange(consts.FieldAllowedManagedKeys) {
		config.AllowedManagedKeys = expandStringSlice(d.Get(consts.FieldAllowedManagedKeys).(*schema.Set).List())
	}

	if d.HasChange(consts.FieldPassthroughRequestHeaders) {
		config.PassthroughRequestHeaders = expandStringSlice(d.Get(consts.FieldPassthroughRequestHeaders).([]interface{}))
	}

	fmt.Println("-- about to check if allowed response headers field has changed --")

	if d.HasChange(consts.FieldAllowedResponseHeaders) {
		var headers *[]string

		oldVal, newVal := d.GetChange(consts.FieldAllowedResponseHeaders)
		fmt.Printf("-- oldVal = %#v, newVal = %#v\n", oldVal, newVal)
		if newVal != nil {
			fmt.Println("-- newVal is not nil")
			if raw, ok := newVal.([]interface{}); ok {
				fmt.Printf("-- raw = %#v\n", raw)
				if len(raw) > 0 {
					x := expandStringSlice(raw)
					headers = &x
				} else {
					headers = &[]string{}
				}
			} else {
				fmt.Println("-- newVal type assertion failed")
			}
		} else {
			// field was omitted
			fmt.Println("-- setting headers to nil")
			headers = nil
		}

		config.AllowedResponseHeaders = headers

		// fmt.Println("-- yes, allowed response headers field has changed --")
		// raw := d.Get(consts.FieldAllowedResponseHeaders)
		// fmt.Printf("-- raw = %#v\n", raw)
		// x := expandStringSlice(d.Get(consts.FieldAllowedResponseHeaders).([]interface{}))
		// fmt.Printf("-- x = %#v\n", x)
		// if len(x) > 0 {
		// 	fmt.Println("-- x is NOT empty, setting it")
		// 	config.AllowedResponseHeaders = &x
		// } else {
		// 	fmt.Println("-- x is empty, not including it")
		// }
		// config.AllowedResponseHeaders = expandStringSlice(d.Get(consts.FieldAllowedResponseHeaders).([]interface{}))
	}

	if d.HasChange(consts.FieldDelegatedAuthAccessors) {
		config.DelegatedAuthAccessors = expandStringSlice(d.Get(consts.FieldDelegatedAuthAccessors).([]interface{}))
	}

	if d.HasChange(consts.FieldListingVisibility) {
		config.ListingVisibility = d.Get(consts.FieldListingVisibility).(string)
	}

	if d.HasChange(consts.FieldPluginVersion) {
		config.PluginVersion = d.Get(consts.FieldPluginVersion).(string)
	}

	if d.HasChange(consts.FieldIdentityTokenKey) {
		config.IdentityTokenKey = d.Get(consts.FieldIdentityTokenKey).(string)
	}

	log.Printf("[DEBUG] Updating mount %s in Vault", path)

	fmt.Printf("-- here's the final config we're passing to mount tune: %#v\n", config)

	// TODO: remove this work-around once VAULT-5521 is fixed
	var tries int
	for {
		if err := client.Sys().TuneMount(path, config); err != nil {
			if tries > 10 {
				return fmt.Errorf("error updating Vault: %s", err)
			}
			tries++
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

	return readMount(d, meta, excludeType)
}

func mountDelete(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Id()

	log.Printf("[DEBUG] Unmounting %s from Vault", path)

	if err := client.Sys().Unmount(path); err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func mountRead(d *schema.ResourceData, meta interface{}) error {
	return readMount(d, meta, false)
}

func readMount(d *schema.ResourceData, meta interface{}, excludeType bool) error {
	fmt.Println("-- READ GOT CALLED")
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading mount %s from Vault", path)

	ctx := context.Background()
	mount, err := mountutil.GetMount(ctx, client, path)
	fmt.Printf("-- mount = %#v\n", mount)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found, removing from state.", path)
			d.SetId("")
			return nil
		}
		return err
	}

	if !excludeType {
		if cfgType, ok := d.GetOk(consts.FieldType); ok {
			// kv-v2 is an alias for kv, version 2. Vault will report it back as "kv"
			// and requires special handling to avoid perpetual drift.
			if cfgType == "kv-v2" && mount.Type == "kv" && mount.Options["version"] == "2" {
				mount.Type = "kv-v2"

				// The options block may be omitted when specifying kv-v2, but will always
				// be present in Vault's response if version 2. Omit the version setting
				// if it wasn't explicitly set in config.
				if mountOptions(d)["version"] == "" {
					delete(mount.Options, "version")
				}
			}
		}

		d.Set(consts.FieldType, mount.Type)
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
	if err := d.Set(consts.FieldOptions, mount.Options); err != nil {
		return err
	}
	if err := d.Set(consts.FieldSealWrap, mount.SealWrap); err != nil {
		return err
	}
	if err := d.Set(consts.FieldExternalEntropyAccess, mount.ExternalEntropyAccess); err != nil {
		return err
	}
	if err := d.Set(consts.FieldAllowedManagedKeys, mount.Config.AllowedManagedKeys); err != nil {
		return err
	}
	if err := d.Set(consts.FieldPassthroughRequestHeaders, mount.Config.PassthroughRequestHeaders); err != nil {
		return err
	}
	if err := d.Set(consts.FieldAllowedResponseHeaders, mount.Config.AllowedResponseHeaders); err != nil {
		return err
	}

	// @TODO add this back in when Vault 1.16.3 is released
	// if err := d.Set(consts.FieldDelegatedAuthAccessors, mount.Config.DelegatedAuthAccessors); err != nil {
	//	return err
	// }
	if err := d.Set(consts.FieldListingVisibility, mount.Config.ListingVisibility); err != nil {
		return err
	}
	if err := d.Set(consts.FieldIdentityTokenKey, mount.Config.IdentityTokenKey); err != nil {
		return err
	}

	return nil
}

func mountOptions(d *schema.ResourceData) map[string]string {
	options := map[string]string{}
	if opts, ok := d.GetOk(consts.FieldOptions); ok {
		for k, v := range opts.(map[string]interface{}) {
			options[k] = v.(string)
		}
	}
	return options
}
