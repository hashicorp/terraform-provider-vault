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

func kmipSecretListenerResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: kmipSecretListenerCreate,
		ReadContext:   provider.ReadContextWrapper(kmipSecretListenerRead),
		UpdateContext: kmipSecretListenerUpdate,
		DeleteContext: kmipSecretListenerDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where KMIP backend is mounted",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the listener",
			},
			"ca": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the CA to use to generate the server certificate and verify client certificates",
			},
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Host:port address to listen on",
			},
			"additional_client_cas": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Names of additional TLS CAs to use to verify client certificates",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"also_use_legacy_ca": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Use the legacy unnamed CA for verifying client certificates as well",
			},
			"server_ips": {
				Type:        schema.TypeSet,
				Optional:    true,
				Computed:    true,
				Description: "IP SANs to include in listener certificate",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"server_hostnames": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "DNS SANs to include in listener certificate",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"tls_min_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Minimum TLS version to accept (tls12 or tls13)",
			},
			"tls_max_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Maximum TLS version to accept (tls12 or tls13)",
			},
			"tls_cipher_suites": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "TLS cipher suites to allow (does not apply to tls13+)",
			},
		},
	}
}

func kmipSecretListenerCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)
	name := d.Get(consts.FieldName).(string)
	listenerPath := getKMIPListenerPath(d)

	data := kmipSecretListenerRequestData(d)

	log.Printf("[DEBUG] Creating KMIP listener at %q", listenerPath)
	if _, err := client.Logical().WriteWithContext(ctx, listenerPath, data); err != nil {
		return diag.Errorf("error creating KMIP listener %q, err=%s", listenerPath, err)
	}

	d.SetId(listenerPath)

	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	return kmipSecretListenerRead(ctx, d, meta)
}

func kmipSecretListenerRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	listenerPath := d.Id()
	if listenerPath == "" {
		return diag.Errorf("expected a path as ID, got empty string")
	}

	log.Printf("[DEBUG] Reading KMIP listener at %q", listenerPath)
	resp, err := client.Logical().ReadWithContext(ctx, listenerPath)
	if err != nil {
		return diag.Errorf("error reading KMIP listener at %s, err=%s", listenerPath, err)
	}

	if resp == nil {
		log.Printf("[WARN] KMIP listener not found, removing from state")
		d.SetId("")
		return nil
	}

	// Set string fields
	for _, k := range []string{"ca", "address", "tls_min_version", "tls_max_version", "tls_cipher_suites"} {
		if v, ok := resp.Data[k]; ok && v != nil {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error setting state key %q on KMIP listener, err=%s", k, err)
			}
		}
	}

	// Set boolean field
	if v, ok := resp.Data["also_use_legacy_ca"]; ok && v != nil {
		if err := d.Set("also_use_legacy_ca", v); err != nil {
			return diag.Errorf("error setting state key 'also_use_legacy_ca' on KMIP listener, err=%s", err)
		}
	}

	// Set set fields
	for _, k := range []string{"additional_client_cas", "server_ips", "server_hostnames"} {
		if v, ok := resp.Data[k]; ok && v != nil {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error setting state key %q on KMIP listener, err=%s", k, err)
			}
		}
	}

	return nil
}

func kmipSecretListenerUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	listenerPath := d.Id()

	if d.HasChange(consts.FieldPath) {
		newListenerPath := getKMIPListenerPath(d)

		log.Printf("[DEBUG] Confirming KMIP listener exists at %s", newListenerPath)
		resp, err := client.Logical().ReadWithContext(ctx, newListenerPath)
		if err != nil {
			return diag.Errorf("error reading listener at path %s, err=%s", newListenerPath, err)
		}

		if resp == nil {
			return diag.Errorf("error remounting KMIP listener to new backend path %s", newListenerPath)
		}
		d.SetId(newListenerPath)
		listenerPath = newListenerPath
	}

	data := kmipSecretListenerRequestData(d)
	log.Printf("[DEBUG] Updating KMIP listener at %q", listenerPath)

	if _, err := client.Logical().WriteWithContext(ctx, listenerPath, data); err != nil {
		return diag.Errorf("error updating KMIP listener %q, err=%s", listenerPath, err)
	}
	log.Printf("[DEBUG] Updated KMIP listener at %q", listenerPath)

	return kmipSecretListenerRead(ctx, d, meta)
}

func kmipSecretListenerDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	listenerPath := d.Id()

	log.Printf("[DEBUG] Deleting KMIP listener %s", listenerPath)
	_, err := client.Logical().DeleteWithContext(ctx, listenerPath)
	if err != nil {
		if util.Is404(err) {
			log.Printf("[WARN] KMIP listener %q not found, removing from state", listenerPath)
			d.SetId("")
			return nil
		}
		return diag.Errorf("error deleting KMIP listener %s, err=%s", listenerPath, err)
	}
	log.Printf("[DEBUG] Deleted KMIP listener %q", listenerPath)

	return nil
}

func kmipSecretListenerRequestData(d *schema.ResourceData) map[string]interface{} {
	data := make(map[string]interface{})

	// Required fields
	if v, ok := d.GetOk("ca"); ok {
		data["ca"] = v.(string)
	}
	if v, ok := d.GetOk("address"); ok {
		data["address"] = v.(string)
	}

	// Optional string fields
	for _, k := range []string{"tls_min_version", "tls_max_version", "tls_cipher_suites"} {
		if d.IsNewResource() {
			if v, ok := d.GetOk(k); ok {
				data[k] = v.(string)
			}
		} else if d.HasChange(k) {
			data[k] = d.Get(k).(string)
		}
	}

	// Optional boolean field
	if d.IsNewResource() {
		if v, ok := d.GetOkExists("also_use_legacy_ca"); ok {
			data["also_use_legacy_ca"] = v.(bool)
		}
	} else if d.HasChange("also_use_legacy_ca") {
		data["also_use_legacy_ca"] = d.Get("also_use_legacy_ca").(bool)
	}

	// Optional set fields
	for _, k := range []string{"additional_client_cas", "server_ips", "server_hostnames"} {
		if d.IsNewResource() {
			if v, ok := d.GetOk(k); ok {
				data[k] = util.TerraformSetToStringArray(v)
			}
		} else if d.HasChange(k) {
			data[k] = util.TerraformSetToStringArray(d.Get(k))
		}
	}

	return data
}

func getKMIPListenerPath(d *schema.ResourceData) string {
	path := d.Get(consts.FieldPath).(string)
	name := d.Get(consts.FieldName).(string)

	return fmt.Sprintf("%s/listener/%s", path, name)
}

// Made with Bob
