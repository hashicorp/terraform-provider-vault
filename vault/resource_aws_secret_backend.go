// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var awsSecretFields = []string{
	consts.FieldIAMEndpoint,
	consts.FieldSTSEndpoint,
	consts.FieldUsernameTemplate,
}

func awsSecretBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: awsSecretBackendCreate,
		ReadContext:   provider.ReadContextWrapper(awsSecretBackendRead),
		UpdateContext: awsSecretBackendUpdate,
		DeleteContext: awsSecretBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "aws",
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
			consts.FieldAccessKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The AWS Access Key ID to use when generating new credentials.",
				Sensitive:   true,
			},
			consts.FieldSecretKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The AWS Secret Access Key to use when generating new credentials.",
				Sensitive:   true,
			},
			consts.FieldRegion: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The AWS region to make API calls against. Defaults to us-east-1.",
			},
			consts.FieldIAMEndpoint: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a custom HTTP IAM endpoint to use.",
			},
			consts.FieldSTSEndpoint: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a custom HTTP STS endpoint to use.",
			},
			consts.FieldUsernameTemplate: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Template describing how dynamic usernames are generated.",
			},
			consts.FieldLocal: {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Default:     false,
				Description: "Specifies if the secret backend is local only",
			},
			consts.FieldRoleArn: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Role ARN to assume for plugin identity token federation.",
			},
			consts.FieldIdentityTokenAudience: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The audience claim value.",
			},
			consts.FieldIdentityTokenKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The key to use for signing identity tokens.",
			},
			consts.FieldIdentityTokenTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The TTL of generated identity tokens in seconds.",
			},
		},
	}, false)
}

func getMountCustomizeDiffFunc(field string) schema.CustomizeDiffFunc {
	return func(ctx context.Context, diff *schema.ResourceDiff, meta interface{}) error {
		if !diff.HasChange(field) {
			return nil
		}

		o, _ := diff.GetChange(field)
		if o == "" {
			return nil
		}

		// Mount Migration is only available for versions >= 1.10
		remountSupported := provider.IsAPISupported(meta, provider.VaultVersion110)
		disable := diff.Get(consts.FieldDisableRemount).(bool)

		if remountSupported && !disable {
			return nil
		}

		// Mount migration not available
		// Destroy and recreate resource
		return diff.ForceNew(field)
	}
}

func awsSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)
	description := d.Get(consts.FieldDescription).(string)
	defaultTTL := d.Get(consts.FieldDefaultLeaseTTL).(int)
	maxTTL := d.Get(consts.FieldMaxLeaseTTL).(int)
	accessKey := d.Get(consts.FieldAccessKey).(string)
	secretKey := d.Get(consts.FieldSecretKey).(string)
	region := d.Get(consts.FieldRegion).(string)
	local := d.Get(consts.FieldLocal).(bool)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting AWS backend at %q", path)
	mountConfig := api.MountConfigInput{
		DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
		MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
	}
	useAPIVer116 := provider.IsAPISupported(meta, provider.VaultVersion116)
	if useAPIVer116 {
		identityTokenKey := d.Get(consts.FieldIdentityTokenKey).(string)
		if identityTokenKey != "" {
			mountConfig.IdentityTokenKey = identityTokenKey
		}
	}
	err := client.Sys().Mount(path, &api.MountInput{
		Type:        consts.MountTypeAWS,
		Description: description,
		Local:       local,
		Config:      mountConfig,
	})
	if err != nil {
		return diag.Errorf("error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted AWS backend at %q", path)
	d.SetId(path)

	log.Printf("[DEBUG] Writing root credentials to %q", path+"/config/root")
	data := map[string]interface{}{
		consts.FieldAccessKey: accessKey,
		consts.FieldSecretKey: secretKey,
	}
	for _, k := range awsSecretFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v.(string)
		}
	}

	if useAPIVer116 {
		if v, ok := d.GetOk(consts.FieldIdentityTokenAudience); ok && v != "" {
			data[consts.FieldIdentityTokenAudience] = v.(string)
		}
		if v, ok := d.GetOk(consts.FieldRoleArn); ok && v != "" {
			data[consts.FieldRoleArn] = v.(string)
		}
		if v, ok := d.GetOk(consts.FieldIdentityTokenTTL); ok && v != 0 {
			data[consts.FieldIdentityTokenTTL] = v.(int)
		}
	}

	if region != "" {
		data[consts.FieldRegion] = region
	}

	_, err = client.Logical().Write(path+"/config/root", data)
	if err != nil {
		return diag.Errorf("error configuring root credentials for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote root credentials to %q", path+"/config/root")
	if region == "" {
		d.Set(consts.FieldRegion, "us-east-1")
	}
	d.Partial(false)

	return awsSecretBackendRead(ctx, d, meta)
}

func awsSecretBackendRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	useAPIVer116 := provider.IsAPISupported(meta, provider.VaultVersion116)

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading AWS backend mount %q from Vault", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return diag.Errorf("error reading mount %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read AWS backend mount %q from Vault", path)

	// the API always returns the path with a trailing slash, so let's make
	// sure we always specify it as a trailing slash.
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing backend from state.", path)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Read AWS secret backend config/root %s", path)
	resp, err := client.Logical().Read(path + "/config/root")
	if err != nil {
		// This is here to support backwards compatibility with Vault. Read operations on the config/root
		// endpoint were just added and haven't been released yet, and so in currently released versions
		// the read operations return a 405 error. We'll gracefully revert back to the old behavior in that
		// case to allow for a transition period.
		respErr, ok := err.(*api.ResponseError)
		if !ok || respErr.StatusCode != 405 {
			return diag.Errorf("error reading AWS secret backend config/root: %s", err)
		}
		log.Printf("[DEBUG] Unable to read config/root due to old version detected; skipping reading access_key and region parameters")
		resp = nil
	}
	if resp != nil {
		if v, ok := resp.Data[consts.FieldAccessKey].(string); ok {
			d.Set(consts.FieldAccessKey, v)
		}
		// Terrible backwards compatibility hack. Previously, if no region was specified,
		// this provider would just write a region of "us-east-1" into its state. Now that
		// we're actually reading the region out from the backend, if it hadn't been set,
		// it will return an empty string. This could potentially cause unexpected diffs
		// for users of the provider, so to avoid it, we're doing something similar here
		// and injecting a fake region of us-east-1 into the state.
		if v, ok := resp.Data[consts.FieldRegion].(string); ok && v != "" {
			d.Set(consts.FieldRegion, v)
		} else {
			d.Set(consts.FieldRegion, "us-east-1")
		}

		for _, k := range awsSecretFields {
			if v, ok := resp.Data[k]; ok {
				if err := d.Set(k, v); err != nil {
					return diag.Errorf("error reading %s for AWS Secret Backend %q: %q", k, path, err)
				}
			}
		}

		if useAPIVer116 {
			if err := d.Set(consts.FieldIdentityTokenAudience, resp.Data[consts.FieldIdentityTokenAudience]); err != nil {
				return diag.Errorf("error reading %s for AWS Secret Backend %q: %q", consts.FieldIdentityTokenAudience, path, err)
			}
			if err := d.Set(consts.FieldRoleArn, resp.Data[consts.FieldRoleArn]); err != nil {
				return diag.Errorf("error reading %s for AWS Secret Backend %q: %q", consts.FieldRoleArn, path, err)
			}
			if err := d.Set(consts.FieldIdentityTokenTTL, resp.Data[consts.FieldIdentityTokenTTL]); err != nil {
				return diag.Errorf("error reading %s for AWS Secret Backend %q: %q", consts.FieldIdentityTokenTTL, path, err)
			}
		}
	}

	d.Set(consts.FieldPath, path)
	d.Set(consts.FieldDescription, mount.Description)
	d.Set(consts.FieldDefaultLeaseTTL, mount.Config.DefaultLeaseTTL)
	d.Set(consts.FieldMaxLeaseTTL, mount.Config.MaxLeaseTTL)
	d.Set(consts.FieldLocal, mount.Local)
	if useAPIVer116 {
		d.Set(consts.FieldIdentityTokenKey, mount.Config.IdentityTokenKey)
	}

	return nil
}

func awsSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
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
	if d.HasChanges(consts.FieldDefaultLeaseTTL, consts.FieldMaxLeaseTTL, consts.FieldDescription, consts.FieldIdentityTokenKey) {
		description := d.Get(consts.FieldDescription).(string)
		config := api.MountConfigInput{
			Description:     &description,
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get(consts.FieldDefaultLeaseTTL)),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get(consts.FieldMaxLeaseTTL)),
		}

		useAPIVer116 := provider.IsAPISupported(meta, provider.VaultVersion116)
		if useAPIVer116 {
			identityTokenKey := d.Get(consts.FieldIdentityTokenKey).(string)
			if identityTokenKey != "" {
				config.IdentityTokenKey = identityTokenKey
			}
		}
		log.Printf("[DEBUG] Updating mount config input for %q", path)
		err := client.Sys().TuneMount(path, config)
		if err != nil {
			return diag.Errorf("error updating mount config input for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated mount config input for %q", path)
	}
	if d.HasChanges(consts.FieldAccessKey, consts.FieldSecretKey, consts.FieldRegion, consts.FieldIAMEndpoint, consts.FieldSTSEndpoint, consts.FieldIdentityTokenTTL, consts.FieldIdentityTokenAudience, consts.FieldRoleArn) {
		log.Printf("[DEBUG] Updating root credentials at %q", path+"/config/root")
		data := map[string]interface{}{
			consts.FieldAccessKey: d.Get(consts.FieldAccessKey).(string),
			consts.FieldSecretKey: d.Get(consts.FieldSecretKey).(string),
		}

		for _, k := range awsSecretFields {
			if v, ok := d.GetOk(k); ok {
				data[k] = v.(string)
			}
		}

		useAPIVer116 := provider.IsAPISupported(meta, provider.VaultVersion116)
		if useAPIVer116 {
			identityTokenAudience := d.Get(consts.FieldIdentityTokenAudience).(string)
			if identityTokenAudience != "" {
				data[consts.FieldIdentityTokenAudience] = identityTokenAudience
			}
			roleArn := d.Get(consts.FieldRoleArn).(string)
			if roleArn != "" {
				data[consts.FieldRoleArn] = roleArn
			}
			identityTokenTTL := d.Get(consts.FieldIdentityTokenTTL).(int)
			if identityTokenTTL != 0 {
				data[consts.FieldIdentityTokenTTL] = identityTokenTTL
			}
		}

		region := d.Get(consts.FieldRegion).(string)
		if region != "" {
			data[consts.FieldRegion] = region
		}

		_, err := client.Logical().Write(path+"/config/root", data)
		if err != nil {
			return diag.Errorf("error configuring root credentials for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated root credentials at %q", path+"/config/root")
		if region == "" {
			d.Set(consts.FieldRegion, "us-east-1")
		}
	}
	d.Partial(false)
	return awsSecretBackendRead(ctx, d, meta)
}

func awsSecretBackendDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Unmounting AWS backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return diag.Errorf("error unmounting AWS backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted AWS backend %q", path)
	return nil
}
