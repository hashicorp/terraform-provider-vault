// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func nomadSecretAccessBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"backend": {
			Type:        schema.TypeString,
			Default:     "nomad",
			Optional:    true,
			Description: "The mount path for the Nomad backend.",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"address": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Specifies the address of the Nomad instance, provided as "protocol://host:port" like "http://127.0.0.1:4646".`,
		},
		"ca_cert": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `CA certificate to use when verifying Nomad server certificate, must be x509 PEM encoded.`,
		},
		"client_cert": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: `Client certificate used for Nomad's TLS communication, must be x509 PEM encoded and if this is set you need to also set client_key.`,
		},
		"client_key": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: `Client key used for Nomad's TLS communication, must be x509 PEM encoded and if this is set you need to also set client_cert.`,
		},
		"default_lease_ttl_seconds": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `Default lease duration for secrets in seconds.`,
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Human-friendly description of the mount for the backend.`,
		},
		"local": {
			Type:        schema.TypeBool,
			Required:    false,
			Optional:    true,
			Description: `Mark the secrets engine as local-only. Local engines are not replicated or removed by replication. Tolerance duration to use when checking the last rotation time.`,
		},
		"max_lease_ttl_seconds": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
		"max_token_name_length": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `Specifies the maximum length to use for the name of the Nomad token generated with Generate Credential. If omitted, 0 is used and ignored, defaulting to the max value allowed by the Nomad version.`,
		},
		"max_ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
		"token": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: `Specifies the Nomad Management token to use.`,
		},
		"ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
	}
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: createNomadAccessConfigResource,
		UpdateContext: updateNomadAccessConfigResource,
		ReadContext:   provider.ReadContextWrapper(readNomadAccessConfigResource),
		DeleteContext: deleteNomadAccessConfigResource,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldBackend),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}, false)

	// Add common mount schema to the resource
	provider.MustAddSchema(r, getMountSchema(
		consts.FieldPath,
		consts.FieldType,
		consts.FieldDescription,
		consts.FieldDefaultLeaseTTLSeconds,
		consts.FieldMaxLeaseTTLSeconds,
		consts.FieldLocal,
	))

	return r
}

func createNomadAccessConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)

	log.Printf("[DEBUG] Mounting Nomad backend at %q", backend)
	if err := createMount(ctx, d, meta, client, backend, consts.MountTypeNomad); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Mounted Nomad backend at %q", backend)
	d.SetId(backend)

	data := map[string]interface{}{}
	if v, ok := d.GetOkExists("address"); ok {
		data["address"] = v
	}

	if v, ok := d.GetOkExists("ca_cert"); ok {
		data["ca_cert"] = v
	}

	if v, ok := d.GetOkExists("client_cert"); ok {
		data["client_cert"] = v
	}

	if v, ok := d.GetOkExists("client_key"); ok {
		data["client_key"] = v
	}

	if v, ok := d.GetOkExists("max_token_name_length"); ok {
		data["max_token_name_length"] = v
	}

	if v, ok := d.GetOkExists("token"); ok {
		data["token"] = v
	}

	configPath := fmt.Sprintf("%s/config/access", backend)
	log.Printf("[DEBUG] Writing %q", configPath)
	if _, err := client.Logical().WriteWithContext(ctx, configPath, data); err != nil {
		return diag.Errorf("error writing %q: %s", configPath, err)
	}

	dataLease := map[string]interface{}{}
	if v, ok := d.GetOkExists("max_ttl"); ok {
		dataLease["max_ttl"] = v
	}

	if v, ok := d.GetOkExists("ttl"); ok {
		dataLease["ttl"] = v
	}

	configLeasePath := fmt.Sprintf("%s/config/lease", backend)
	log.Printf("[DEBUG] Writing %q", configLeasePath)
	if _, err := client.Logical().WriteWithContext(ctx, configLeasePath, dataLease); err != nil {
		return diag.Errorf("error writing %q: %s", configLeasePath, err)
	}

	log.Printf("[DEBUG] Wrote %q", configLeasePath)
	return readNomadAccessConfigResource(ctx, d, meta)
}

func readNomadAccessConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Id()

	if err := d.Set("backend", backend); err != nil {
		return diag.FromErr(err)
	}
	if err := readMount(ctx, d, meta, true, true); err != nil {
		return diag.FromErr(err)
	}

	configPath := fmt.Sprintf("%s/config/access", backend)
	log.Printf("[DEBUG] Reading %q", configPath)

	resp, err := client.Logical().Read(configPath)
	if err != nil {
		return diag.Errorf("error reading %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Read %q", configPath)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", configPath)
		d.SetId("")
		return nil
	}

	if val, ok := resp.Data["address"]; ok {
		if err := d.Set("address", val); err != nil {
			return diag.Errorf("error setting state key 'address': %s", err)
		}
	}

	if val, ok := resp.Data["ca_cert"]; ok {
		if err := d.Set("ca_cert", val); err != nil {
			return diag.Errorf("error setting state key 'ca_cert': %s", err)
		}
	}

	if val, ok := resp.Data["client_cert"]; ok {
		if err := d.Set("client_cert", val); err != nil {
			return diag.Errorf("error setting state key 'client_cert': %s", err)
		}
	}

	if val, ok := resp.Data["client_key"]; ok {
		if err := d.Set("client_key", val); err != nil {
			return diag.Errorf("error setting state key 'client_key': %s", err)
		}
	}

	if val, ok := resp.Data["max_token_name_length"]; ok {
		if err := d.Set("max_token_name_length", val); err != nil {
			return diag.Errorf("error setting state key 'max_token_name_length': %s", err)
		}
	}

	configLeasePath := fmt.Sprintf("%s/config/lease", d.Id())
	log.Printf("[DEBUG] Reading %q", configLeasePath)

	resp, err = client.Logical().Read(configLeasePath)
	if err != nil {
		return diag.Errorf("error reading %q: %s", configLeasePath, err)
	}
	log.Printf("[DEBUG] Read %q", configLeasePath)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", configLeasePath)
		d.SetId("")
		return nil
	}

	if val, ok := resp.Data["max_ttl"]; ok {
		if err := d.Set("max_ttl", val); err != nil {
			return diag.Errorf("error setting state key 'max_ttl': %s", err)
		}
	}

	if val, ok := resp.Data["ttl"]; ok {
		if err := d.Set("ttl", val); err != nil {
			return diag.Errorf("error setting state key 'ttl': %s", err)
		}
	}

	return nil
}

func updateNomadAccessConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	data := map[string]interface{}{}

	if err := updateMount(ctx, d, meta, true, true); err != nil {
		return diag.FromErr(err)
	}

	// Remount backend after updating in case needed.
	// we remount in a separate step due to the resource using the legacy "backend" field
	backend, err := util.Remount(d, client, consts.FieldBackend, false)
	if err != nil {
		return diag.FromErr(err)
	}

	configPath := fmt.Sprintf("%s/config/access", backend)
	log.Printf("[DEBUG] Updating %q", configPath)

	if raw, ok := d.GetOk("address"); ok {
		data["address"] = raw
	}

	if raw, ok := d.GetOk("ca_cert"); ok {
		data["ca_cert"] = raw
	}

	if raw, ok := d.GetOk("client_cert"); ok {
		data["client_cert"] = raw
	}

	if raw, ok := d.GetOk("client_key"); ok {
		data["client_key"] = raw
	}

	if raw, ok := d.GetOk("max_token_name_length"); ok {
		data["max_token_name_length"] = raw
	}

	if raw, ok := d.GetOk("token"); ok {
		data["token"] = raw
	}

	if _, err := client.Logical().Write(configPath, data); err != nil {
		return diag.Errorf("error updating access config %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Updated %q", configPath)

	configLeasePath := fmt.Sprintf("%s/config/lease", backend)
	log.Printf("[DEBUG] Updating %q", configLeasePath)

	dataLease := map[string]interface{}{}

	if raw, ok := d.GetOk("max_ttl"); ok {
		dataLease["max_ttl"] = raw
	}

	if raw, ok := d.GetOk("ttl"); ok {
		dataLease["ttl"] = raw
	}

	if _, err := client.Logical().Write(configLeasePath, dataLease); err != nil {
		return diag.Errorf("error updating lease config %q: %s", configLeasePath, err)
	}

	log.Printf("[DEBUG] Updated %q", configLeasePath)
	return readNomadAccessConfigResource(ctx, d, meta)
}

func deleteNomadAccessConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	vaultPath := d.Id()
	log.Printf("[DEBUG] Unmounting Nomad backend %q", vaultPath)

	err := client.Sys().Unmount(vaultPath)
	if err != nil && util.Is404(err) {
		log.Printf("[WARN] %q not found, removing from state", vaultPath)
		d.SetId("")
		return diag.Errorf("error unmounting Nomad backend from %q: %s", vaultPath, err)
	} else if err != nil {
		return diag.Errorf("error unmounting Nomad backend from %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Unmounted Nomad backend %q", vaultPath)
	return nil
}
