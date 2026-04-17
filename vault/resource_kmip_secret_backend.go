// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var kmipAPIFields = []string{
	"default_tls_client_key_bits",
	"default_tls_client_key_type",
	"default_tls_client_ttl",
	"listen_addrs",
	"server_hostnames",
	"server_ips",
	"tls_ca_key_bits",
	"tls_ca_key_type",
	"tls_min_version",
}

func kmipSecretBackendResource() *schema.Resource {
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: kmipSecretBackendCreate,
		ReadContext:   provider.ReadContextWrapper(kmipSecretBackendRead),
		UpdateContext: kmipSecretBackendUpdate,
		DeleteContext: kmipSecretBackendDelete,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where KMIP secret backend will be mounted",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend",
			},
			"listen_addrs": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Addresses the KMIP server should listen on (host:port)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"server_hostnames": {
				Type:        schema.TypeSet,
				Optional:    true,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Hostnames to include in the server's TLS certificate as SAN DNS names. The first will be used as the common name (CN)",
			},
			"server_ips": {
				Type:        schema.TypeSet,
				Optional:    true,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "IPs to include in the server's TLS certificate as SAN IP addresses",
			},

			"tls_ca_key_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "CA key type, rsa or ec",
			},
			"tls_ca_key_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "CA key bits, valid values depend on key type",
			},
			"tls_min_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Minimum TLS version to accept",
			},
			"default_tls_client_key_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Client certificate key type, rsa or ec",
			},
			"default_tls_client_key_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Client certificate key bits, valid values depend on key type",
			},
			"default_tls_client_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Client certificate TTL in seconds",
			},
		},
	}, false)

	// Add common mount schema to the resource
	provider.MustAddSchema(r, getMountSchema(
		consts.FieldPath,
		consts.FieldType,
		consts.FieldDescription,
	))

	return r
}

func kmipSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Get("path").(string)

	log.Printf("[DEBUG] Mounting KMIP backend at %q", path)
	if err := createMount(ctx, d, meta, client, path, consts.MountTypeKMIP); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Mounted KMIP backend at %q", path)
	d.SetId(path)

	return kmipSecretBackendUpdate(ctx, d, meta)
}

func kmipSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	if !d.IsNewResource() {
		if err := updateMount(ctx, d, meta, true, false); err != nil {
			return diag.FromErr(err)
		}
	}

	path := d.Id()

	data := map[string]interface{}{}
	configPath := fmt.Sprintf("%s/config", path)
	log.Printf("[DEBUG] Updating %q", configPath)

	for _, k := range kmipAPIFields {
		if d.HasChange(k) {
			v, ok := d.GetOk(k)
			if ok {
				switch v.(type) {
				case *schema.Set:
					data[k] = util.TerraformSetToStringArray(v)
				default:
					data[k] = v
				}
			} else {
				// Explicitly send empty value when field is being cleared
				switch d.Get(k).(type) {
				case *schema.Set:
					data[k] = []string{}
				default:
					data[k] = nil
				}
			}
		}
	}

	if _, err := client.Logical().WriteWithContext(ctx, configPath, data); err != nil {
		return diag.Errorf("error updating KMIP config %q, err=%s", configPath, err)
	}

	log.Printf("[DEBUG] Updated %q", configPath)

	return kmipSecretBackendRead(ctx, d, meta)
}

func kmipSecretBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Reading KMIP config at %s/config", path)
	resp, err := client.Logical().ReadWithContext(ctx, path+"/config")
	if err != nil {
		return diag.Errorf("error reading KMIP config at %q/config: err=%s", path, err)
	}

	if resp == nil {
		log.Printf("[WARN] KMIP config not found, removing from state")
		d.SetId("")

		return nil
	}

	for _, k := range kmipAPIFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q on KMIP config, err=%s", k, err)
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

func kmipSecretBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()
	log.Printf("[DEBUG] Unmounting KMIP backend %q", path)

	if err := client.Sys().UnmountWithContext(ctx, path); err != nil {
		if util.Is404(err) {
			log.Printf("[WARN] %q not found, removing from state", path)
			d.SetId("")

			return diag.Errorf("error unmounting KMIP backend from %q, err=%s", path, err)
		}

		return diag.Errorf("error unmounting KMIP backend from %q, err=%s", path, err)
	}

	log.Printf("[DEBUG] Unmounted KMIP backend %q", path)

	return nil
}
