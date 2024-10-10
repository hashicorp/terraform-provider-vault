// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func terraformCloudSecretBackendResource() *schema.Resource {
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: terraformCloudSecretBackendCreate,
		ReadContext:   provider.ReadContextWrapper(terraformCloudSecretBackendRead),
		UpdateContext: terraformCloudSecretBackendUpdate,
		DeleteContext: terraformCloudSecretBackendDelete,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldBackend),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     consts.MountTypeTerraform,
				Description: "Unique name of the Vault Terraform Cloud mount to configure",
				StateFunc: func(s interface{}) string {
					return strings.Trim(s.(string), "/")
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},
			"token": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the Terraform Cloud access token to use.",
				Sensitive:   true,
			},
			"address": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "https://app.terraform.io",
				Description: "Specifies the address of the Terraform Cloud instance, provided as \"host:port\" like \"127.0.0.1:8500\".",
			},
			"base_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "/api/v2/",
				Description: "Specifies the base path for the Terraform Cloud or Enterprise API.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "0",
				Description: "Default lease duration for secrets in seconds",
			},
			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "0",
				Description: "Maximum possible lease duration for secrets in seconds",
			},
		},
	}, false)

	// Add common mount schema to the resource
	provider.MustAddSchema(r, getMountSchema(
		consts.FieldPath,
		consts.FieldType,
		consts.FieldDescription,
		consts.FieldDefaultLeaseTTL,
		consts.FieldMaxLeaseTTL,
	))

	return r
}

func terraformCloudSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	address := d.Get("address").(string)
	token := d.Get("token").(string)
	basePath := d.Get("base_path").(string)

	configPath := terraformCloudSecretBackendConfigPath(backend)

	log.Printf("[DEBUG] Mounting Terraform Cloud backend at %q", backend)

	if err := createMount(ctx, d, meta, client, backend, consts.MountTypeTerraform); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Mounted Terraform Cloud backend at %q", backend)
	d.SetId(backend)

	log.Printf("[DEBUG] Writing Terraform Cloud configuration to %q", configPath)
	data := map[string]interface{}{
		"address":   address,
		"token":     token,
		"base_path": basePath,
	}
	if _, err := client.Logical().WriteWithContext(ctx, configPath, data); err != nil {
		return diag.Errorf("Error writing Terraform Cloud configuration for %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Wrote Terraform Cloud configuration to %q", configPath)

	return terraformCloudSecretBackendRead(ctx, d, meta)
}

func terraformCloudSecretBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Id()
	configPath := terraformCloudSecretBackendConfigPath(backend)

	if err := d.Set("backend", backend); err != nil {
		return diag.FromErr(err)
	}
	if err := readMount(ctx, d, meta, true); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading %s from Vault", configPath)
	secret, err := client.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}

	if err := d.Set("address", secret.Data["address"].(string)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("base_path", secret.Data["base_path"].(string)); err != nil {
		return diag.FromErr(err)

	}

	return nil
}

func terraformCloudSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Id()
	configPath := terraformCloudSecretBackendConfigPath(backend)

	backend, e = util.Remount(d, client, consts.FieldBackend, false)
	if e != nil {
		return diag.FromErr(e)
	}

	if err := updateMount(ctx, d, meta, true); err != nil {
		return diag.FromErr(err)
	}
	if d.HasChange("address") || d.HasChange("token") || d.HasChange("base_path") {
		log.Printf("[DEBUG] Updating Terraform Cloud configuration at %q", configPath)
		data := map[string]interface{}{
			"address":   d.Get("address").(string),
			"token":     d.Get("token").(string),
			"base_path": d.Get("base_path").(string),
		}
		if _, err := client.Logical().WriteWithContext(ctx, configPath, data); err != nil {
			return diag.Errorf("Error configuring Terraform Cloud configuration for %q: %s", backend, err)
		}
		log.Printf("[DEBUG] Updated Terraform Cloud configuration at %q", configPath)
		if err := d.Set("address", data["address"]); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("token", data["token"]); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("base_path", data["base_path"]); err != nil {
			return diag.FromErr(err)
		}
	}
	return terraformCloudSecretBackendRead(ctx, d, meta)
}

func terraformCloudSecretBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Id()

	log.Printf("[DEBUG] Unmounting Terraform Cloud backend %q", backend)
	err := client.Sys().UnmountWithContext(ctx, backend)
	if err != nil {
		return diag.Errorf("Error unmounting Terraform Cloud backend from %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Unmounted Terraform Cloud backend %q", backend)
	return nil
}

func terraformCloudSecretBackendConfigPath(backend string) string {
	return strings.Trim(backend, "/") + "/config"
}
