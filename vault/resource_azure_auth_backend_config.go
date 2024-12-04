// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var azureAuthBackendConfigFromPathRegex = regexp.MustCompile("^auth/(.+)/config$")

func azureAuthBackendConfigResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: azureAuthBackendWrite,
		ReadContext:   provider.ReadContextWrapper(azureAuthBackendRead),
		UpdateContext: azureAuthBackendWrite,
		DeleteContext: azureAuthBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "azure",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
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
			consts.FieldResource: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The configured URL for the application registered in Azure Active Directory.",
			},
			consts.FieldEnvironment: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Azure cloud environment. Valid values: AzurePublicCloud, AzureUSGovernmentCloud, AzureChinaCloud, AzureGermanCloud.",
			},
			consts.FieldIdentityTokenAudience: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The audience claim value.",
			},
			consts.FieldIdentityTokenTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The TTL of generated identity tokens in seconds.",
			},
		},
	}
}

func azureAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	config, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	// if backend comes from the config, it won't have the StateFunc
	// applied yet, so we need to apply it again.
	backend := d.Get(consts.FieldBackend).(string)
	tenantId := d.Get(consts.FieldTenantID).(string)
	clientId := d.Get(consts.FieldClientID).(string)
	clientSecret := d.Get(consts.FieldClientSecret).(string)
	resource := d.Get(consts.FieldResource).(string)
	environment := d.Get(consts.FieldEnvironment).(string)
	identityTokenAud := d.Get(consts.FieldIdentityTokenAudience).(string)
	identityTokenTTL := d.Get(consts.FieldIdentityTokenTTL).(int)

	path := azureAuthBackendConfigPath(backend)

	data := map[string]interface{}{
		consts.FieldTenantID:     tenantId,
		consts.FieldClientID:     clientId,
		consts.FieldClientSecret: clientSecret,
		consts.FieldResource:     resource,
		consts.FieldEnvironment:  environment,
	}

	useAPIVer117Ent := provider.IsAPISupported(meta, provider.VaultVersion117) && provider.IsEnterpriseSupported(meta)
	if useAPIVer117Ent {
		data[consts.FieldIdentityTokenAudience] = identityTokenAud
		data[consts.FieldIdentityTokenTTL] = identityTokenTTL
	}

	log.Printf("[DEBUG] Writing Azure auth backend config to %q", path)
	_, err := config.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error writing to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Azure auth backend config to %q", path)

	d.SetId(path)

	return azureAuthBackendRead(ctx, d, meta)
}

func azureAuthBackendConfigBackendFromPath(path string) (string, error) {
	if !azureAuthBackendConfigFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := azureAuthBackendConfigFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func azureAuthBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	config, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()
	log.Printf("[DEBUG] Reading Azure auth backend config")
	secret, err := config.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading Azure auth backend config from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Azure auth backend config")

	if secret == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", path)
		d.SetId("")
		return nil
	}
	backend, err := azureAuthBackendConfigBackendFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for azure auth backend config: %s", path, err)
	}

	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}

	fields := []string{
		consts.FieldTenantID,
		consts.FieldClientID,
		consts.FieldClientSecret,
		consts.FieldResource,
		consts.FieldEnvironment,
	}
	for _, k := range fields {
		if v, ok := secret.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	useAPIVer117Ent := provider.IsAPISupported(meta, provider.VaultVersion117) && provider.IsEnterpriseSupported(meta)
	if useAPIVer117Ent {
		if v, ok := secret.Data[consts.FieldIdentityTokenAudience]; ok {
			if err := d.Set(consts.FieldIdentityTokenAudience, v); err != nil {
				return diag.FromErr(err)
			}
		}
		if v, ok := secret.Data[consts.FieldIdentityTokenTTL]; ok {
			if err := d.Set(consts.FieldIdentityTokenTTL, v); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return nil
}

func azureAuthBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	config, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	log.Printf("[DEBUG] Deleting Azure auth backend config from %q", d.Id())
	_, err := config.Logical().DeleteWithContext(ctx, d.Id())
	if err != nil {
		return diag.Errorf("error deleting Azure auth backend config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Deleted Azure auth backend config from %q", d.Id())

	return nil
}

func azureAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}
