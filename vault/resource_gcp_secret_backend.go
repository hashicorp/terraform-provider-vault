// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func gcpSecretBackendResource(name string) *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		Create:        gcpSecretBackendCreate,
		Read:          ReadWrapper(gcpSecretBackendRead),
		Update:        gcpSecretBackendUpdate,
		Delete:        gcpSecretBackendDelete,
		Exists:        gcpSecretBackendExists,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     consts.MountTypeGCP,
				Description: "Path to mount the backend at.",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.HasSuffix(value, "/") {
						errs = append(errs, fmt.Errorf("path cannot end in '/'"))
					}
					return
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},
			"credentials": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "JSON-encoded credentials to use to connect to GCP",
				Sensitive:   true,
				// We rebuild the attached JSON string to a simple singleline
				// string. This makes terraform not want to change when an extra
				// space is included in the JSON string. It is also necesarry
				// when disable_read is false for comparing values.
				StateFunc:    NormalizeDataJSONFunc(name),
				ValidateFunc: ValidateDataJSONFunc(name),
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "",
				Description: "Default lease duration for secrets in seconds",
			},
			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "",
				Description: "Maximum possible lease duration for secrets in seconds",
			},
			"local": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Computed:    false,
				ForceNew:    true,
				Description: "Local mount flag that can be explicitly set to true to enforce local mount in HA environment",
			},
		},
	})
}

func gcpSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get("path").(string)
	description := d.Get("description").(string)
	defaultTTL := d.Get("default_lease_ttl_seconds").(int)
	maxTTL := d.Get("max_lease_ttl_seconds").(int)
	credentials := d.Get("credentials").(string)
	local := d.Get("local").(bool)

	configPath := gcpSecretBackendConfigPath(path)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting GCP backend at %q", path)
	err := client.Sys().Mount(path, &api.MountInput{
		Type:        consts.MountTypeGCP,
		Description: description,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
			MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
		},
		Local: local,
	})
	if err != nil {
		return fmt.Errorf("error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted GCP backend at %q", path)
	d.SetId(path)

	log.Printf("[DEBUG] Writing GCP configuration to %q", configPath)
	if credentials != "" {
		data := map[string]interface{}{
			"credentials": credentials,
		}
		if _, err := client.Logical().Write(configPath, data); err != nil {
			return fmt.Errorf("error writing GCP configuration for %q: %s", path, err)
		}
	} else {
		log.Printf("[DEBUG] No credentials configured")
	}
	log.Printf("[DEBUG] Wrote GCP configuration to %q", configPath)
	d.Partial(false)

	return gcpSecretBackendRead(d, meta)
}

func gcpSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading GCP backend mount %q from Vault", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading mount %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read GCP backend mount %q from Vault", path)

	// the API always returns the path with a trailing slash, so let's make
	// sure we always specify it as a trailing slash.
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing backend from state.", path)
		d.SetId("")
		return nil
	}

	d.Set("path", path)
	d.Set("description", mount.Description)
	d.Set("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL)
	d.Set("local", mount.Local)

	return nil
}

func gcpSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	d.Partial(true)

	path, err := util.Remount(d, client, consts.FieldPath, false)
	if err != nil {
		return err
	}

	if d.HasChange("default_lease_ttl_seconds") || d.HasChange("max_lease_ttl_seconds") {
		config := api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		}
		log.Printf("[DEBUG] Updating lease TTLs for %q", path)
		err := client.Sys().TuneMount(path, config)
		if err != nil {
			return fmt.Errorf("error updating mount TTLs for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated lease TTLs for %q", path)
	}

	if d.HasChange("credentials") {
		data := map[string]interface{}{
			"credentials": d.Get("credentials"),
		}
		configPath := gcpSecretBackendConfigPath(path)
		if _, err := client.Logical().Write(configPath, data); err != nil {
			return fmt.Errorf("error writing GCP credentials for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated credentials for %q", path)
	}

	d.Partial(false)
	return gcpSecretBackendRead(d, meta)
}

func gcpSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Unmounting GCP backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("error unmounting GCP backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted GCP backend %q", path)
	return nil
}

func gcpSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if GCP backend exists at %q", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if GCP backend exists at %q", path)
	_, ok := mounts[strings.Trim(path, "/")+"/"]
	return ok, nil
}

func gcpSecretBackendConfigPath(backend string) string {
	return strings.Trim(backend, "/") + "/config"
}
