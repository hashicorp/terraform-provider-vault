// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	automatedrotationutil "github.com/hashicorp/terraform-provider-vault/internal/rotation"

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
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
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
			consts.FieldDefaultLeaseTTLSeconds: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Default lease duration for secrets in seconds",
			},
			consts.FieldMaxLeaseTTLSeconds: {
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
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The AWS Secret Access Key to use when generating new credentials.",
				Sensitive:     true,
				ConflictsWith: []string{consts.FieldSecretKeyWO},
			},
			consts.FieldSecretKeyWO: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The AWS Secret Access Key to use when generating new credentials. This is a write-only field and will not be read back from Vault.",
				Sensitive:     true,
				WriteOnly:     true,
				ConflictsWith: []string{consts.FieldSecretKey},
			},
			consts.FieldSecretKeyWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "A version counter for the write-only secret_key_wo field. Incrementing this value will trigger an update to the secret_key.",
				RequiredWith: []string{consts.FieldSecretKeyWO},
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
			consts.FieldSTSRegion: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a custom STS region to use.",
			},
			consts.FieldSTSFallbackEndpoints: {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "Specifies a list of custom STS fallback endpoints to use (in order).",
			},
			consts.FieldSTSFallbackRegions: {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "Specifies a list of custom STS fallback regions to use (in order).",
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
			consts.FieldMaxRetries: {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     -1,
				Description: "Number of max retries the client should use for recoverable errors.",
			},
		},
	}, false)

	// Add common mount schema to the resource
	provider.MustAddSchema(r, getMountSchema(
		consts.FieldPath,
		consts.FieldType,
		consts.FieldDescription,
		consts.FieldDefaultLeaseTTLSeconds,
		consts.FieldMaxLeaseTTLSeconds,
		consts.FieldIdentityTokenKey,
		consts.FieldLocal,
	))

	// Add common automated root rotation schema to the resource
	provider.MustAddSchema(r, provider.GetAutomatedRootRotationSchema())

	return r
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
	useAPIVer119 := provider.IsAPISupported(meta, provider.VaultVersion119)
	isEnterprise := provider.IsEnterpriseSupported(meta)
	useAPIVer116Enterprise := provider.IsAPISupported(meta, provider.VaultVersion116) && isEnterprise

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)
	accessKey := d.Get(consts.FieldAccessKey).(string)
	region := d.Get(consts.FieldRegion).(string)

	// Handle secret_key - check both regular and write-only fields
	var secretKey string
	if v, ok := d.GetOk(consts.FieldSecretKey); ok {
		secretKey = v.(string)
	} else if d.IsNewResource() || d.HasChange(consts.FieldSecretKeyWOVersion) {
		// Use GetRawConfigAt for write-only fields
		p := cty.GetAttrPath(consts.FieldSecretKeyWO)
		woVal, _ := d.GetRawConfigAt(p)
		if !woVal.IsNull() {
			secretKey = woVal.AsString()
		}
	}

	d.Partial(true)
	log.Printf("[DEBUG] Mounting AWS backend at %q", path)

	if err := createMount(ctx, d, meta, client, path, consts.MountTypeAWS); err != nil {
		return diag.FromErr(err)
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

	if useAPIVer119 {
		if v, ok := d.GetOk(consts.FieldSTSFallbackEndpoints); ok {
			data[consts.FieldSTSFallbackEndpoints] = util.ToStringArray(v.([]interface{}))
		}

		if v, ok := d.GetOk(consts.FieldSTSFallbackRegions); ok {
			data[consts.FieldSTSFallbackRegions] = util.ToStringArray(v.([]interface{}))
		}

		if v, ok := d.GetOk(consts.FieldSTSRegion); ok {
			data[consts.FieldSTSRegion] = v.(string)
		}

		// parse automated root rotation fields if Enterprise 1.19 server
		if isEnterprise {
			automatedrotationutil.ParseAutomatedRotationFields(d, data)
		}
	}

	if useAPIVer116Enterprise {
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

	if v, ok := d.GetOk(consts.FieldMaxRetries); ok {
		data[consts.FieldMaxRetries] = v.(int)
	}

	if region != "" {
		data[consts.FieldRegion] = region
	}

	_, err := client.Logical().WriteWithContext(ctx, path+"/config/root", data)
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

func awsSecretBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	isEnterprise := provider.IsEnterpriseSupported(meta)
	useAPIVer116 := provider.IsAPISupported(meta, provider.VaultVersion116) && isEnterprise
	useAPIVer119 := provider.IsAPISupported(meta, provider.VaultVersion119)

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Read AWS secret backend config/root %s", path)
	resp, err := client.Logical().ReadWithContext(ctx, path+"/config/root")
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

		if useAPIVer119 {
			if v, ok := resp.Data[consts.FieldSTSFallbackEndpoints]; ok {
				if err := d.Set(consts.FieldSTSFallbackEndpoints, v); err != nil {
					return diag.Errorf("error reading %s for AWS Secret Backend %q: %q", consts.FieldSTSFallbackEndpoints, path, err)
				}
			}

			if v, ok := resp.Data[consts.FieldSTSFallbackRegions]; ok {
				if err := d.Set(consts.FieldSTSFallbackRegions, v); err != nil {
					return diag.Errorf("error reading %s for AWS Secret Backend %q: %q", consts.FieldSTSFallbackRegions, path, err)
				}
			}

			if v, ok := resp.Data[consts.FieldSTSRegion]; ok {
				if err := d.Set(consts.FieldSTSRegion, v); err != nil {
					return diag.Errorf("error reading %s for AWS Secret Backend %q: %q", consts.FieldSTSRegion, path, err)
				}
			}

			if isEnterprise {
				if err := automatedrotationutil.PopulateAutomatedRotationFields(d, resp, path); err != nil {
					return diag.FromErr(err)
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

		if v, ok := resp.Data[consts.FieldMaxRetries]; ok {
			if err := d.Set(consts.FieldMaxRetries, v); err != nil {
				return diag.Errorf("error reading %s for AWS Secret Backend %q: %q", consts.FieldMaxRetries, path, err)
			}
		}
	}

	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}

	if err := readMount(ctx, d, meta, true, false); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func awsSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	isEnterprise := provider.IsEnterpriseSupported(meta)
	useAPIVer116 := provider.IsAPISupported(meta, provider.VaultVersion116) && isEnterprise
	useAPIVer119 := provider.IsAPISupported(meta, provider.VaultVersion119)

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	d.Partial(true)

	if err := updateMount(ctx, d, meta, true, false); err != nil {
		return diag.FromErr(err)
	}
	path := d.Id()
	if d.HasChanges(consts.FieldAccessKey,
		consts.FieldSecretKey, consts.FieldSecretKeyWOVersion, consts.FieldRegion, consts.FieldIAMEndpoint,
		consts.FieldSTSEndpoint, consts.FieldSTSFallbackEndpoints, consts.FieldSTSRegion, consts.FieldSTSFallbackRegions,
		consts.FieldIdentityTokenTTL, consts.FieldIdentityTokenAudience, consts.FieldRoleArn, consts.FieldMaxRetries,
		consts.FieldRotationSchedule,
		consts.FieldRotationPeriod,
		consts.FieldRotationWindow,
		consts.FieldDisableAutomatedRotation,
	) {
		log.Printf("[DEBUG] Updating root credentials at %q", path+"/config/root")

		// Handle secret_key - check both regular and write-only fields
		var secretKey string
		if v, ok := d.GetOk(consts.FieldSecretKey); ok {
			secretKey = v.(string)
		} else if d.HasChange(consts.FieldSecretKeyWOVersion) {
			// Use GetRawConfig for write-only fields
			woVal := d.GetRawConfig().GetAttr(consts.FieldSecretKeyWO)
			if !woVal.IsNull() {
				secretKey = woVal.AsString()
			}
		}

		data := map[string]interface{}{
			consts.FieldAccessKey: d.Get(consts.FieldAccessKey).(string),
		}

		if secretKey != "" {
			data[consts.FieldSecretKey] = secretKey
		}

		for _, k := range awsSecretFields {
			if v, ok := d.GetOk(k); ok {
				data[k] = v.(string)
			}
		}

		if useAPIVer119 {
			if v, ok := d.GetOk(consts.FieldSTSFallbackEndpoints); ok {
				data[consts.FieldSTSFallbackEndpoints] = util.ToStringArray(v.([]interface{}))
			}

			if v, ok := d.GetOk(consts.FieldSTSFallbackRegions); ok {
				data[consts.FieldSTSFallbackRegions] = util.ToStringArray(v.([]interface{}))
			}

			if v, ok := d.GetOk(consts.FieldSTSRegion); ok {
				data[consts.FieldSTSRegion] = v.(string)
			}

			// parse automated root rotation fields if Enterprise 1.19 server
			if isEnterprise {
				automatedrotationutil.ParseAutomatedRotationFields(d, data)
			}
		}

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

		data[consts.FieldMaxRetries] = d.Get(consts.FieldMaxRetries)

		region := d.Get(consts.FieldRegion).(string)
		if region != "" {
			data[consts.FieldRegion] = region
		}

		_, err := client.Logical().WriteWithContext(ctx, path+"/config/root", data)
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

func awsSecretBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Unmounting AWS backend %q", path)
	err := client.Sys().UnmountWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error unmounting AWS backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted AWS backend %q", path)
	return nil
}
