// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func tencentCloudSecretBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: tencentCloudSecretBackendCreate,
		ReadContext:   provider.ReadContextWrapper(tencentCloudSecretBackendRead),
		UpdateContext: tencentCloudSecretBackendUpdate,
		DeleteContext: tencentCloudSecretBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "tencentcloud",
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
			consts.FieldDescription: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			consts.FieldLocal: {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Default:     false,
				Description: "Specifies if the secret backend is local only",
			},
			consts.FieldDefaultLeaseTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Default lease duration for secrets in seconds",
			},
			consts.FieldMaxLeaseTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Maximum possible lease duration for secrets in seconds",
			},
			consts.FieldSecretID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Tencent Cloud Access Key ID to use when generating new credentials.",
				Sensitive:   true,
			},
			consts.FieldSecretKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Tencent Cloud Secret Access Key to use when generating new credentials.",
				Sensitive:   true,
			},
		},
	}, false)
}

func tencentCloudSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)
	description := d.Get(consts.FieldDescription).(string)
	defaultTTL := d.Get(consts.FieldDefaultLeaseTTL).(int)
	maxTTL := d.Get(consts.FieldMaxLeaseTTL).(int)
	secretId := d.Get(consts.FieldSecretID).(string)
	secretKey := d.Get(consts.FieldSecretKey).(string)
	local := d.Get(consts.FieldLocal).(bool)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting TencentCloud backend at %q", path)
	mountConfig := api.MountConfigInput{
		DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
		MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
	}

	err := client.Sys().MountWithContext(ctx, path, &api.MountInput{
		Type:        "vault-plugin-secrets-tencentcloud",
		Description: description,
		Local:       local,
		Config:      mountConfig,
	})
	if err != nil {
		return diag.Errorf("error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted Tencent CLoud backend at %q", path)
	d.SetId(path)

	log.Printf("[DEBUG] Writing root credentials to %q", path+"/config")
	data := map[string]interface{}{
		consts.FieldSecretID:  secretId,
		consts.FieldSecretKey: secretKey,
	}

	time.Sleep(3 * time.Second)

	_, err = client.Logical().WriteWithContext(ctx, path+"/config", data)
	if err != nil {
		return diag.Errorf("error configuring root credentials for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote root credentials to %q", path+"/config")
	d.Partial(false)

	return tencentCloudSecretBackendRead(ctx, d, meta)
}

func tencentCloudSecretBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading Tencent Cloud backend mount %q from Vault", path)

	mount, err := mountutil.GetMount(ctx, client, path)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found, removing from state.", path)
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Read Tencent Cloud backend mount %q from Vault", path)

	log.Printf("[DEBUG] Read Tencent Cloud secret backend config/root %s", path)
	resp, err := client.Logical().ReadWithContext(ctx, path+"/config")
	if err != nil {
		// This is here to support backwards compatibility with Vault. Read operations on the config/root
		// endpoint were just added and haven't been released yet, and so in currently released versions
		// the read operations return a 405 error. We'll gracefully revert back to the old behavior in that
		// case to allow for a transition period.
		respErr, ok := err.(*api.ResponseError)
		if !ok || respErr.StatusCode != 405 {
			return diag.Errorf("error reading Tencent Cloud secret backend config/root: %s", err)
		}
		log.Printf("[DEBUG] Unable to read config/root due to old version detected; skipping reading access_key and region parameters")
		resp = nil
	}
	if resp != nil {
		if v, ok := resp.Data[consts.FieldSecretID].(string); ok {
			_ = d.Set(consts.FieldSecretID, v)
		}
		if v, ok := resp.Data[consts.FieldSecretKey].(string); ok {
			_ = d.Set(consts.FieldSecretKey, v)
		}
		// Terrible backwards compatibility hack. Previously, if no region was specified,
		// this provider would just write a region of "us-east-1" into its state. Now that
		// we're actually reading the region out from the backend, if it hadn't been set,
		// it will return an empty string. This could potentially cause unexpected diffs
		// for users of the provider, so to avoid it, we're doing something similar here
		// and injecting a fake region of us-east-1 into the state.

	}

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

	return nil
}

func tencentCloudSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

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
	if d.HasChanges(consts.FieldDefaultLeaseTTL, consts.FieldMaxLeaseTTL, consts.FieldDescription) {
		description := d.Get(consts.FieldDescription).(string)
		config := api.MountConfigInput{
			Description:     &description,
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get(consts.FieldDefaultLeaseTTL)),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get(consts.FieldMaxLeaseTTL)),
		}

		log.Printf("[DEBUG] Updating mount config input for %q", path)
		err := client.Sys().TuneMountWithContext(ctx, path, config)
		if err != nil {
			return diag.Errorf("error updating mount config input for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated mount config input for %q", path)
	}
	if d.HasChanges(consts.FieldSecretID, consts.FieldSecretKey) {
		log.Printf("[DEBUG] Updating root credentials at %q", path+"/config/root")
		data := map[string]interface{}{
			consts.FieldSecretID:  d.Get(consts.FieldSecretID).(string),
			consts.FieldSecretKey: d.Get(consts.FieldSecretKey).(string),
		}

		_, err := client.Logical().WriteWithContext(ctx, path+"/config", data)
		if err != nil {
			return diag.Errorf("error configuring root credentials for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated root credentials at %q", path+"/config")
	}
	d.Partial(false)
	return tencentCloudSecretBackendRead(ctx, d, meta)
}

func tencentCloudSecretBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Unmounting Tencent Cloud backend %q", path)
	err := client.Sys().UnmountWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error unmounting Tencent Cloud backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted Tencent Cloud backend %q", path)
	return nil
}
