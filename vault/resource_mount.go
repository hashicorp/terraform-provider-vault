// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

type schemaMap map[string]*schema.Schema

func getMountSchema(excludes ...string) schemaMap {
	s := schemaMap{
		"path": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    false,
			Description: "Where the secret backend will be mounted",
		},
		"type": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Type of the backend, such as 'aws'",
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Required:    false,
			Description: "Human-friendly description of the mount",
		},
		"default_lease_ttl_seconds": {
			Type:        schema.TypeInt,
			Required:    false,
			Optional:    true,
			Computed:    true,
			ForceNew:    false,
			Description: "Default lease duration for tokens and secrets in seconds",
		},

		"max_lease_ttl_seconds": {
			Type:        schema.TypeInt,
			Required:    false,
			Optional:    true,
			Computed:    true,
			ForceNew:    false,
			Description: "Maximum possible lease duration for tokens and secrets in seconds",
		},

		"audit_non_hmac_request_keys": {
			Type:        schema.TypeList,
			Computed:    true,
			Optional:    true,
			Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the request data object.",
			Elem:        &schema.Schema{Type: schema.TypeString},
		},

		"audit_non_hmac_response_keys": {
			Type:        schema.TypeList,
			Computed:    true,
			Optional:    true,
			Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the response data object.",
			Elem:        &schema.Schema{Type: schema.TypeString},
		},

		"accessor": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Accessor of the mount",
		},

		"local": {
			Type:        schema.TypeBool,
			Required:    false,
			Optional:    true,
			Computed:    false,
			ForceNew:    true,
			Description: "Local mount flag that can be explicitly set to true to enforce local mount in HA environment",
		},

		"options": {
			Type:        schema.TypeMap,
			Required:    false,
			Optional:    true,
			Computed:    false,
			ForceNew:    false,
			Description: "Specifies mount type specific options that are passed to the backend",
		},

		"seal_wrap": {
			Type:        schema.TypeBool,
			Required:    false,
			Optional:    true,
			ForceNew:    true,
			Computed:    true,
			Description: "Enable seal wrapping for the mount, causing values stored by the mount to be wrapped by the seal's encryption capability",
		},

		"external_entropy_access": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			ForceNew:    true,
			Description: "Enable the secrets engine to access Vault's external entropy source",
		},

		"allowed_managed_keys": {
			Type:        schema.TypeSet,
			Optional:    true,
			ForceNew:    true,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Description: "List of managed key registry entry names that the mount in question is allowed to access",
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

	path := d.Get("path").(string)
	if err := createMount(d, client, path, d.Get("type").(string)); err != nil {
		return err
	}

	d.SetId(path)

	return mountRead(d, meta)
}

func createMount(d *schema.ResourceData, client *api.Client, path string, mountType string) error {
	input := &api.MountInput{
		Type:        mountType,
		Description: d.Get("description").(string),
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		},
		Local:                 d.Get("local").(bool),
		Options:               mountOptions(d),
		SealWrap:              d.Get("seal_wrap").(bool),
		ExternalEntropyAccess: d.Get("external_entropy_access").(bool),
	}

	if v, ok := d.GetOk("audit_non_hmac_request_keys"); ok {
		input.Config.AuditNonHMACRequestKeys = expandStringSlice(v.([]interface{}))
	}
	if v, ok := d.GetOk("audit_non_hmac_response_keys"); ok {
		input.Config.AuditNonHMACResponseKeys = expandStringSlice(v.([]interface{}))
	}

	if v, ok := d.GetOk("allowed_managed_keys"); ok {
		input.Config.AllowedManagedKeys = expandStringSlice(v.(*schema.Set).List())
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
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	config := api.MountConfigInput{
		DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
		MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		Options:         mountOptions(d),
	}

	if d.HasChange("audit_non_hmac_request_keys") {
		config.AuditNonHMACRequestKeys = expandStringSlice(d.Get("audit_non_hmac_request_keys").([]interface{}))
	}

	if d.HasChange("audit_non_hmac_response_keys") {
		config.AuditNonHMACResponseKeys = expandStringSlice(d.Get("audit_non_hmac_response_keys").([]interface{}))
	}

	if d.HasChange("description") {
		description := fmt.Sprintf("%s", d.Get("description"))
		config.Description = &description
	}

	path := d.Id()

	if d.HasChange("path") {
		newPath := d.Get("path").(string)

		log.Printf("[DEBUG] Remount %s to %s in Vault", path, newPath)

		err := client.Sys().Remount(d.Id(), newPath)
		if err != nil {
			return fmt.Errorf("error remounting in Vault: %s", err)
		}

		d.SetId(newPath)
		path = newPath
	}

	if d.HasChange("allowed_managed_keys") {
		config.AllowedManagedKeys = expandStringSlice(d.Get("allowed_managed_keys").(*schema.Set).List())
	}

	log.Printf("[DEBUG] Updating mount %s in Vault", path)

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

// getMountIfPresent  will fetch the secret mount at the given path.
func getMountIfPresent(client *api.Client, path string) (*api.MountOutput, error) {
	mount, err := client.Sys().GetMount(path)
	if err != nil {
		return nil, fmt.Errorf("error reading from Vault: %s", err)
	}
	if mount.Accessor == "" {
		return nil, fmt.Errorf("mount not found: %s", err)
	}
	return mount, nil
}

func readMount(d *schema.ResourceData, meta interface{}, excludeType bool) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading mount %s from Vault", path)

	mount, err := getMountIfPresent(client, path)
	if mount == nil {
		d.SetId("")
		return nil
	}

	if err != nil {
		return err
	}

	if !excludeType {
		if cfgType, ok := d.GetOk("type"); ok {
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

		d.Set("type", mount.Type)
	}

	d.Set("path", path)
	d.Set("description", mount.Description)
	d.Set("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL)
	d.Set("audit_non_hmac_request_keys", mount.Config.AuditNonHMACRequestKeys)
	d.Set("audit_non_hmac_response_keys", mount.Config.AuditNonHMACResponseKeys)
	d.Set("accessor", mount.Accessor)
	d.Set("local", mount.Local)
	d.Set("options", mount.Options)
	d.Set("seal_wrap", mount.SealWrap)
	d.Set("external_entropy_access", mount.ExternalEntropyAccess)
	d.Set("allowed_managed_keys", mount.Config.AllowedManagedKeys)

	return nil
}

func mountOptions(d *schema.ResourceData) map[string]string {
	options := map[string]string{}
	if opts, ok := d.GetOk("options"); ok {
		for k, v := range opts.(map[string]interface{}) {
			options[k] = v.(string)
		}
	}
	return options
}
