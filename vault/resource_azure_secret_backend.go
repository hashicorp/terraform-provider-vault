// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	automatedrotationutil "github.com/hashicorp/terraform-provider-vault/internal/rotation"
)

func azureSecretBackendResource() *schema.Resource {
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
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
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The client secret for credentials to query the Azure APIs",
				Sensitive:     true,
				ConflictsWith: []string{consts.FieldClientSecretWO},
			},
			consts.FieldClientSecretWO: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The client secret for credentials to query the Azure APIs. This is a write-only field and will not be read back from Vault.",
				Sensitive:     true,
				WriteOnly:     true,
				ConflictsWith: []string{consts.FieldClientSecret},
			},
			consts.FieldClientSecretWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "A version counter for the write-only client_secret_wo field. Incrementing this value will trigger an update to the client secret.",
				RequiredWith: []string{consts.FieldClientSecretWO},
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
			consts.FieldRootPasswordTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The TTL in seconds of the root password in Azure when rotate-root generates a new client secret",
			},
		},
	}, false)

	// Add common mount schema to the resource
	provider.MustAddSchema(r, getMountSchema(
		consts.FieldPath,
		consts.FieldType,
		consts.FieldDescription,
		consts.FieldIdentityTokenKey,
	))

	provider.MustAddSchema(r, provider.GetAutomatedRootRotationSchema())

	return r
}

func azureSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)
	configPath := azureSecretBackendPath(path)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Azure backend at %q", path)

	if err := createMount(ctx, d, meta, client, path, consts.MountTypeAzure); err != nil {
		return diag.FromErr(err)
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

	log.Printf("[DEBUG] Read Azure secret Backend config %s", path)
	resp, err := client.Logical().ReadWithContext(ctx, azureSecretBackendPath(path))
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}

	for _, k := range []string{
		consts.FieldClientID,
		consts.FieldSubscriptionID,
		consts.FieldTenantID,
		consts.FieldRootPasswordTTL,
	} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
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

	useAPIVer117Ent := provider.IsAPISupported(meta, provider.VaultVersion117) && provider.IsEnterpriseSupported(meta)
	if useAPIVer117Ent {
		if err := d.Set(consts.FieldIdentityTokenAudience, resp.Data[consts.FieldIdentityTokenAudience]); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set(consts.FieldIdentityTokenTTL, resp.Data[consts.FieldIdentityTokenTTL]); err != nil {
			return diag.FromErr(err)
		}
	}

	useAPIVer119Ent := provider.IsAPISupported(meta, provider.VaultVersion119) && provider.IsEnterpriseSupported(meta)
	if useAPIVer119Ent {
		if err := automatedrotationutil.PopulateAutomatedRotationFields(d, resp, d.Id()); err != nil {
			return diag.FromErr(err)
		}
	}

	if err := readMount(ctx, d, meta, true, false); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func azureSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	if err := updateMount(ctx, d, meta, true, false); err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()

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

func azureSecretBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Unmounting Azure backend %q", path)
	err := client.Sys().UnmountWithContext(ctx, path)
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
		consts.FieldSubscriptionID,
	}

	data := make(map[string]interface{})
	for _, k := range fields {
		if d.IsNewResource() {
			data[k] = d.Get(k)
		} else if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	// Handle client_secret and client_secret_wo
	if v, ok := d.GetOk(consts.FieldClientSecret); ok {
		if d.IsNewResource() || d.HasChange(consts.FieldClientSecret) {
			data[consts.FieldClientSecret] = v.(string)
		}
	} else if d.IsNewResource() || d.HasChange(consts.FieldClientSecretWOVersion) {
		p := cty.GetAttrPath(consts.FieldClientSecretWO)
		woVal, _ := d.GetRawConfigAt(p)
		if !woVal.IsNull() {
			data[consts.FieldClientSecret] = woVal.AsString()
		}
	}

	useAPIVer115 := provider.IsAPISupported(meta, provider.VaultVersion115)
	if useAPIVer115 {
		if v, ok := d.GetOk(consts.FieldRootPasswordTTL); ok && v != 0 {
			data[consts.FieldRootPasswordTTL] = v.(int)
		}
	}

	useAPIVer117Ent := provider.IsAPISupported(meta, provider.VaultVersion117) && provider.IsEnterpriseSupported(meta)
	if useAPIVer117Ent {
		if v, ok := d.GetOk(consts.FieldIdentityTokenAudience); ok && v != "" {
			data[consts.FieldIdentityTokenAudience] = v.(string)
		}
		if v, ok := d.GetOk(consts.FieldIdentityTokenTTL); ok && v != 0 {
			data[consts.FieldIdentityTokenTTL] = v.(int)
		}
	}

	useAPIVer119Ent := provider.IsAPISupported(meta, provider.VaultVersion119) && provider.IsEnterpriseSupported(meta)
	if useAPIVer119Ent {
		automatedrotationutil.ParseAutomatedRotationFields(d, data)
	}

	return data
}
