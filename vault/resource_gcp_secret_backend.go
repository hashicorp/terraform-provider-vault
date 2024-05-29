// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func gcpSecretBackendResource(name string) *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: gcpSecretBackendCreate,
		ReadContext:   provider.ReadContextWrapper(gcpSecretBackendRead),
		UpdateContext: gcpSecretBackendUpdate,
		DeleteContext: gcpSecretBackendDelete,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
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
			consts.FieldCredentials: {
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
			consts.FieldDescription: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			consts.FieldDefaultLeaseTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "",
				Description: "Default lease duration for secrets in seconds",
			},
			consts.FieldMaxLeaseTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "",
				Description: "Maximum possible lease duration for secrets in seconds",
			},
			consts.FieldLocal: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Computed:    false,
				ForceNew:    true,
				Description: "Local mount flag that can be explicitly set to true to enforce local mount in HA environment",
			},
			consts.FieldIdentityTokenKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The key to use for signing identity tokens.",
			},
			consts.FieldIdentityTokenAudience: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The audience claim value for plugin identity tokens.",
			},
			consts.FieldIdentityTokenTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The TTL of generated tokens.",
			},
			consts.FieldServiceAccountEmail: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Service Account to impersonate for plugin workload identity federation.",
			},
			consts.FieldAccessor: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Accessor of the created GCP mount.",
			},
		},
	}, false)
}

func gcpSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)
	description := d.Get(consts.FieldDescription).(string)
	defaultTTL := d.Get(consts.FieldDefaultLeaseTTL).(int)
	maxTTL := d.Get(consts.FieldMaxLeaseTTL).(int)
	local := d.Get(consts.FieldLocal).(bool)
	identityTokenKey := d.Get(consts.FieldIdentityTokenKey).(string)

	configPath := gcpSecretBackendConfigPath(path)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting GCP backend at %q", path)
	useAPIVer117Ent := provider.IsAPISupported(meta, provider.VaultVersion117Ent)

	mountConfig := api.MountConfigInput{
		DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
		MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
	}

	// ID Token Key is only used in GCP mounts for 1.17+
	if useAPIVer117Ent {
		mountConfig.IdentityTokenKey = identityTokenKey
	}

	err := client.Sys().Mount(path, &api.MountInput{
		Type:        consts.MountTypeGCP,
		Description: description,
		Config:      mountConfig,
		Local:       local,
	})
	if err != nil {
		return diag.Errorf("error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted GCP backend at %q", path)
	d.SetId(path)

	log.Printf("[DEBUG] Writing GCP configuration to %q", configPath)

	data := map[string]interface{}{}
	fields := []string{
		consts.FieldCredentials,
	}

	if useAPIVer117Ent {
		fields = append(fields,
			consts.FieldIdentityTokenAudience,
			consts.FieldIdentityTokenTTL,
			consts.FieldServiceAccountEmail,
		)
	}

	for _, k := range fields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	if _, err := client.Logical().WriteWithContext(ctx, configPath, data); err != nil {
		return diag.Errorf("error writing GCP configuration for %q: %s", path, err)
	}

	log.Printf("[DEBUG] Wrote GCP configuration to %q", configPath)
	d.Partial(false)

	return gcpSecretBackendRead(ctx, d, meta)
}

func gcpSecretBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading GCP backend mount %q from Vault", path)

	mount, err := mountutil.GetMount(ctx, client, path)
	if errors.Is(err, mountutil.ErrMountNotFound) {
		log.Printf("[WARN] Mount %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Read GCP backend mount %q from Vault", path)

	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldDescription, mount.Description); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldDefaultLeaseTTL, mount.Config.DefaultLeaseTTL); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldMaxLeaseTTL, mount.Config.MaxLeaseTTL); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldLocal, mount.Local); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldAccessor, mount.Accessor); err != nil {
		return diag.FromErr(err)
	}

	// read and set config if needed
	if provider.IsAPISupported(meta, provider.VaultVersion117Ent) {
		resp, err := client.Logical().ReadWithContext(ctx, gcpSecretBackendConfigPath(path))
		if err != nil {
			return diag.FromErr(err)
		}
		fields := []string{
			consts.FieldIdentityTokenAudience,
			consts.FieldIdentityTokenTTL,
			consts.FieldServiceAccountEmail,
		}

		for _, k := range fields {
			if v, ok := resp.Data[k]; ok {
				if err := d.Set(k, v); err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}

	return nil
}

func gcpSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	d.Partial(true)

	path, err := util.Remount(d, client, consts.FieldPath, false)
	if err != nil {
		return diag.FromErr(err)
	}

	useAPIVer117Ent := provider.IsAPISupported(meta, provider.VaultVersion117Ent)

	if d.HasChanges(consts.FieldDefaultLeaseTTL, consts.FieldMaxLeaseTTL, consts.FieldIdentityTokenKey) {
		config := api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get(consts.FieldDefaultLeaseTTL)),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get(consts.FieldMaxLeaseTTL)),
		}

		if useAPIVer117Ent {
			config.IdentityTokenKey = d.Get(consts.FieldIdentityTokenKey).(string)
		}

		log.Printf("[DEBUG] Updating mount config for %q", path)
		err := client.Sys().TuneMountWithContext(ctx, path, config)
		if err != nil {
			return diag.Errorf("error updating mount config for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated mount config for %q", path)
	}

	data := make(map[string]interface{})

	if d.HasChange(consts.FieldCredentials) {
		data[consts.FieldCredentials] = d.Get(consts.FieldCredentials)
	}
	if useAPIVer117Ent {
		if d.HasChange(consts.FieldIdentityTokenAudience) {
			data[consts.FieldIdentityTokenAudience] = d.Get(consts.FieldIdentityTokenAudience)
		}

		if d.HasChange(consts.FieldIdentityTokenTTL) {
			data[consts.FieldIdentityTokenTTL] = d.Get(consts.FieldIdentityTokenTTL)
		}

		if d.HasChange(consts.FieldServiceAccountEmail) {
			data[consts.FieldServiceAccountEmail] = d.Get(consts.FieldServiceAccountEmail)
		}
	}

	configPath := gcpSecretBackendConfigPath(path)
	if _, err := client.Logical().WriteWithContext(ctx, configPath, data); err != nil {
		return diag.Errorf("error writing GCP credentials for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated credentials for %q", path)

	d.Partial(false)
	return gcpSecretBackendRead(ctx, d, meta)
}

func gcpSecretBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Unmounting GCP backend %q", path)
	err := client.Sys().UnmountWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error unmounting GCP backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted GCP backend %q", path)
	return nil
}

func gcpSecretBackendConfigPath(backend string) string {
	return strings.Trim(backend, "/") + "/config"
}
