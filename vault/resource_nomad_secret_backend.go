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
	"github.com/hashicorp/terraform-provider-vault/util"
)

func nomadSecretAccessBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldBackend: {
			Type:        schema.TypeString,
			Default:     "nomad",
			Optional:    true,
			Description: "The mount path for the Nomad backend.",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		consts.FieldAddress: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Specifies the address of the Nomad instance, provided as " +
				`"protocol://host:port" like "http://127.0.0.1:4646".`,
		},
		consts.FieldCACert: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `CA certificate to use when verifying Nomad server certificate, must be x509 PEM encoded.`,
		},
		consts.FieldClientCert: {
			Type:      schema.TypeString,
			Optional:  true,
			Sensitive: true,
			Description: "Client certificate used for Nomad's TLS communication, " +
				"must be x509 PEM encoded and if this is set you need to also set client_key.",
		},
		consts.FieldClientKey: {
			Type:      schema.TypeString,
			Optional:  true,
			Sensitive: true,
			Description: "Client key used for Nomad's TLS communication, " +
				"must be x509 PEM encoded and if this is set you need to also set client_cert.",
			ConflictsWith: []string{consts.FieldClientKeyWO},
		},
		consts.FieldClientKeyWO: {
			Type:      schema.TypeString,
			Optional:  true,
			Sensitive: true,
			WriteOnly: true,
			Description: "Write-only client key used for Nomad's TLS communication, " +
				"must be x509 PEM encoded and if this is set you need to also set client_cert.",
			ConflictsWith: []string{consts.FieldClientKey},
		},
		consts.FieldClientKeyWOVersion: {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  `Version counter for write-only client_key.`,
			RequiredWith: []string{consts.FieldClientKeyWO},
		},
		consts.FieldDefaultLeaseTTLSeconds: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `Default lease duration for secrets in seconds.`,
		},
		consts.FieldDescription: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Human-friendly description of the mount for the backend.`,
		},
		consts.FieldLocal: {
			Type:     schema.TypeBool,
			Required: false,
			Optional: true,
			Description: "Mark the secrets engine as local-only. Local engines are not replicated or " +
				"removed by replication. Tolerance duration to use when checking the last rotation time.",
		},
		consts.FieldMaxLeaseTTLSeconds: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
		consts.FieldMaxTokenNameLength: {
			Type:     schema.TypeInt,
			Optional: true,
			Computed: true,
			Description: "Specifies the maximum length to use for the name of the Nomad token generated " +
				"with Generate Credential. If omitted, 0 is used and ignored, defaulting to the max value " +
				"allowed by the Nomad version.",
		},
		consts.FieldMaxTTL: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
		consts.FieldToken: {
			Type:          schema.TypeString,
			Optional:      true,
			Sensitive:     true,
			Description:   `Specifies the Nomad Management token to use.`,
			ConflictsWith: []string{consts.FieldTokenWO},
		},
		consts.FieldTokenWO: {
			Type:          schema.TypeString,
			Optional:      true,
			Sensitive:     true,
			WriteOnly:     true,
			Description:   `Write-only Nomad Management token to use.`,
			ConflictsWith: []string{consts.FieldToken},
		},
		consts.FieldTokenWOVersion: {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  `Version counter for write-only token.`,
			RequiredWith: []string{consts.FieldTokenWO},
		},
		consts.FieldTTL: {
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

	backend := d.Get(consts.FieldBackend).(string)

	log.Printf("[DEBUG] Mounting Nomad backend at %q", backend)
	if err := createMount(ctx, d, meta, client, backend, consts.MountTypeNomad); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Mounted Nomad backend at %q", backend)
	d.SetId(backend)

	data := map[string]interface{}{}
	if v, ok := d.GetOk(consts.FieldAddress); ok {
		data[consts.FieldAddress] = v
	}

	if v, ok := d.GetOk(consts.FieldCACert); ok {
		data[consts.FieldCACert] = v
	}

	if v, ok := d.GetOk(consts.FieldClientCert); ok {
		data[consts.FieldClientCert] = v
	}

	if v, ok := d.GetOk(consts.FieldClientKey); ok {
		data[consts.FieldClientKey] = v.(string)
	} else if clientKeyWo, _ := d.GetRawConfigAt(cty.GetAttrPath(consts.FieldClientKeyWO)); !clientKeyWo.IsNull() {
		data[consts.FieldClientKey] = clientKeyWo.AsString()
	}

	if v, ok := d.GetOk(consts.FieldMaxTokenNameLength); ok {
		data[consts.FieldMaxTokenNameLength] = v
	}

	if v, ok := d.GetOk(consts.FieldToken); ok {
		data[consts.FieldToken] = v.(string)
	} else if tokenWo, _ := d.GetRawConfigAt(cty.GetAttrPath(consts.FieldTokenWO)); !tokenWo.IsNull() {
		data[consts.FieldToken] = tokenWo.AsString()
	}

	configPath := fmt.Sprintf("%s/config/access", backend)
	log.Printf("[DEBUG] Writing %q", configPath)
	if _, err := client.Logical().WriteWithContext(ctx, configPath, data); err != nil {
		return diag.Errorf("error writing %q: %s", configPath, err)
	}

	dataLease := map[string]interface{}{}
	if v, ok := d.GetOk(consts.FieldMaxTTL); ok {
		dataLease[consts.FieldMaxTTL] = v
	}

	if v, ok := d.GetOk(consts.FieldTTL); ok {
		dataLease[consts.FieldTTL] = v
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

	if err := d.Set(consts.FieldBackend, backend); err != nil {
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

	if val, ok := resp.Data[consts.FieldAddress]; ok {
		if err := d.Set(consts.FieldAddress, val); err != nil {
			return diag.Errorf("error setting state key '%s': %s", consts.FieldAddress, err)
		}
	}

	if val, ok := resp.Data[consts.FieldCACert]; ok {
		if err := d.Set(consts.FieldCACert, val); err != nil {
			return diag.Errorf("error setting state key '%s': %s", consts.FieldCACert, err)
		}
	}

	if val, ok := resp.Data[consts.FieldClientCert]; ok {
		if err := d.Set(consts.FieldClientCert, val); err != nil {
			return diag.Errorf("error setting state key '%s': %s", consts.FieldClientCert, err)
		}
	}

	// Don't read back client_key if using write-only version
	if _, ok := d.GetOk(consts.FieldClientKeyWO); !ok {
		if val, ok := resp.Data[consts.FieldClientKey]; ok {
			if err := d.Set(consts.FieldClientKey, val); err != nil {
				return diag.Errorf("error setting state key '%s': %s", consts.FieldClientKey, err)
			}
		}
	}

	if val, ok := resp.Data[consts.FieldMaxTokenNameLength]; ok {
		if err := d.Set(consts.FieldMaxTokenNameLength, val); err != nil {
			return diag.Errorf("error setting state key '%s': %s", consts.FieldMaxTokenNameLength, err)
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

	if val, ok := resp.Data[consts.FieldMaxTTL]; ok {
		if err := d.Set(consts.FieldMaxTTL, val); err != nil {
			return diag.Errorf("error setting state key '%s': %s", consts.FieldMaxTTL, err)
		}
	}

	if val, ok := resp.Data[consts.FieldTTL]; ok {
		if err := d.Set(consts.FieldTTL, val); err != nil {
			return diag.Errorf("error setting state key '%s': %s", consts.FieldTTL, err)
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

	if raw, ok := d.GetOk(consts.FieldAddress); ok {
		data[consts.FieldAddress] = raw
	}

	if raw, ok := d.GetOk(consts.FieldCACert); ok {
		data[consts.FieldCACert] = raw
	}

	if raw, ok := d.GetOk(consts.FieldClientCert); ok {
		data[consts.FieldClientCert] = raw
	}

	if raw, ok := d.GetOk(consts.FieldClientKey); ok {
		data[consts.FieldClientKey] = raw.(string)
	} else if d.HasChange(consts.FieldClientKeyWOVersion) {
		clientKeyWo, _ := d.GetRawConfigAt(cty.GetAttrPath(consts.FieldClientKeyWO))
		if !clientKeyWo.IsNull() {
			data[consts.FieldClientKey] = clientKeyWo.AsString()
		}
	}

	if raw, ok := d.GetOk(consts.FieldMaxTokenNameLength); ok {
		data[consts.FieldMaxTokenNameLength] = raw
	}

	if raw, ok := d.GetOk(consts.FieldToken); ok {
		data[consts.FieldToken] = raw.(string)
	} else if d.HasChange(consts.FieldTokenWOVersion) {
		tokenWo, _ := d.GetRawConfigAt(cty.GetAttrPath(consts.FieldTokenWO))
		if !tokenWo.IsNull() {
			data[consts.FieldToken] = tokenWo.AsString()
		}
	}

	if _, err := client.Logical().Write(configPath, data); err != nil {
		return diag.Errorf("error updating access config %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Updated %q", configPath)

	configLeasePath := fmt.Sprintf("%s/config/lease", backend)
	log.Printf("[DEBUG] Updating %q", configLeasePath)

	dataLease := map[string]interface{}{}

	if raw, ok := d.GetOk(consts.FieldMaxTTL); ok {
		dataLease[consts.FieldMaxTTL] = raw
	}

	if raw, ok := d.GetOk(consts.FieldTTL); ok {
		dataLease[consts.FieldTTL] = raw
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
