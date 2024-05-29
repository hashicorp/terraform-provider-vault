// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"

	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func azureSecretBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: azureSecretBackendCreate,
		ReadContext:   provider.ReadContextWrapper(azureSecretBackendRead),
		UpdateContext: azureSecretBackendUpdate,
		DeleteContext: azureSecretBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "azure",
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
			consts.FieldUseMSGraphAPI: {
				Deprecated:  "This field is not supported in Vault-1.12+ and is the default behavior. This field will be removed in future version of the provider.",
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Use the Microsoft Graph API. Should be set to true on vault-1.10+",
			},
			consts.FieldSubscriptionID: {
				Type:        schema.TypeString,
				ForceNew:    true,
				Required:    true,
				Sensitive:   true,
				Description: "The subscription id for the Azure Active Directory.",
			},
			consts.FieldTenantID: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The tenant id for the Azure Active Directory organization.",
				Sensitive:   true,
			},
			consts.FieldClientID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The client id for credentials to query the Azure APIs. Currently read permissions to query compute resources are required.",
				Sensitive:   true,
			},
			consts.FieldClientSecret: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The client secret for credentials to query the Azure APIs",
				Sensitive:   true,
			},
			consts.FieldEnvironment: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "AzurePublicCloud",
				Description: "The Azure cloud environment. Valid values: AzurePublicCloud, AzureUSGovernmentCloud, AzureChinaCloud, AzureGermanCloud.",
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

func azureSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)
	description := d.Get(consts.FieldDescription).(string)
	configPath := azureSecretBackendPath(path)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Azure backend at %q", path)

	mountConfig := api.MountConfigInput{}
	useAPIVer117Ent := provider.IsAPISupported(meta, provider.VaultVersion117Ent)
	if useAPIVer117Ent {
		identityTokenKey := d.Get(consts.FieldIdentityTokenKey).(string)
		if identityTokenKey != "" {
			mountConfig.IdentityTokenKey = identityTokenKey
		}
	}
	input := &api.MountInput{
		Type:        "azure",
		Description: description,
		Config:      mountConfig,
	}
	if err := client.Sys().Mount(path, input); err != nil {
		return diag.Errorf("error mounting to %q: %s", path, err)
	}

	log.Printf("[DEBUG] Mounted Azure backend at %q", path)
	d.SetId(path)

	log.Printf("[DEBUG] Writing Azure configuration to %q", configPath)
	data := azureSecretBackendRequestData(d, meta)
	if _, err := client.Logical().WriteWithContext(ctx, configPath, data); err != nil {
		return diag.Errorf("error writing Azure configuration for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Azure configuration to %q", configPath)
	d.Partial(false)

	return azureSecretBackendRead(ctx, d, meta)
}

func azureSecretBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading Azure backend mount %q from Vault", path)

	mount, err := mountutil.GetMount(context.Background(), client, path)
	if errors.Is(err, mountutil.ErrMountNotFound) {
		log.Printf("[WARN] Mount %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Read Azure backend mount %q from Vault", path)

	log.Printf("[DEBUG] Read Azure secret Backend config %s", path)
	resp, err := client.Logical().ReadWithContext(ctx, azureSecretBackendPath(path))
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}

	for _, k := range []string{consts.FieldClientID, consts.FieldSubscriptionID, consts.FieldTenantID} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	skipMSGraphAPI := provider.IsAPISupported(meta, provider.VaultVersion112)
	if !skipMSGraphAPI {
		if v, ok := resp.Data[consts.FieldUseMSGraphAPI]; ok {
			if err := d.Set(consts.FieldUseMSGraphAPI, v); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	if v, ok := resp.Data[consts.FieldEnvironment]; ok && v.(string) != "" {
		if err := d.Set(consts.FieldEnvironment, v); err != nil {
			return diag.FromErr(err)
		}
	} else {
		if err := d.Set(consts.FieldEnvironment, "AzurePublicCloud"); err != nil {
			return diag.FromErr(err)
		}
	}

	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldDescription, mount.Description); err != nil {
		return diag.FromErr(err)
	}

	useAPIVer117Ent := provider.IsAPISupported(meta, provider.VaultVersion117Ent)
	if useAPIVer117Ent {
		if err := d.Set(consts.FieldIdentityTokenKey, mount.Config.IdentityTokenKey); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set(consts.FieldIdentityTokenAudience, resp.Data[consts.FieldIdentityTokenAudience]); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set(consts.FieldIdentityTokenTTL, resp.Data[consts.FieldIdentityTokenTTL]); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func azureSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	path, err := util.Remount(d, client, consts.FieldPath, false)
	if err != nil {
		return diag.FromErr(err)
	}

	data := azureSecretBackendRequestData(d, meta)
	if len(data) > 0 {
		_, err := client.Logical().WriteWithContext(ctx, azureSecretBackendPath(path), data)
		if err != nil {
			return diag.Errorf("error writing config for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated Azure Backend Config at %q", azureSecretBackendPath(path))
	}

	return azureSecretBackendRead(ctx, d, meta)
}

func azureSecretBackendDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Unmounting Azure backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return diag.Errorf("error unmounting Azure backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted Azure backend %q", path)
	return nil
}

func azureSecretBackendPath(path string) string {
	return strings.Trim(path, "/") + "/config"
}

func azureSecretBackendRequestData(d *schema.ResourceData, meta interface{}) map[string]interface{} {
	fields := []string{
		consts.FieldClientID,
		consts.FieldEnvironment,
		consts.FieldTenantID,
		consts.FieldClientSecret,
		consts.FieldSubscriptionID,
	}

	skipMSGraphAPI := provider.IsAPISupported(meta, provider.VaultVersion112)

	if _, ok := d.GetOk(consts.FieldUseMSGraphAPI); ok {
		if skipMSGraphAPI {
			log.Printf("ignoring this field because Vault version is greater than 1.12")
		}
	}

	if !skipMSGraphAPI {
		fields = append(fields, consts.FieldUseMSGraphAPI)
	}

	data := make(map[string]interface{})
	for _, k := range fields {
		if d.IsNewResource() {
			data[k] = d.Get(k)
		} else if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	useAPIVer117Ent := provider.IsAPISupported(meta, provider.VaultVersion117Ent)
	if useAPIVer117Ent {
		if v, ok := d.GetOk(consts.FieldIdentityTokenAudience); ok && v != "" {
			data[consts.FieldIdentityTokenAudience] = v.(string)
		}
		if v, ok := d.GetOk(consts.FieldIdentityTokenTTL); ok && v != 0 {
			data[consts.FieldIdentityTokenTTL] = v.(int)
		}
	}

	return data
}
