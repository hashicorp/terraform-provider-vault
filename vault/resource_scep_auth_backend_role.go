// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"log"
	"strings"
)

var scepAuthStringFields = []string{
	consts.FieldName,
	consts.FieldDisplayName,
	consts.FieldAuthType,
	consts.FieldChallenge,
}

func scepAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldBackend: {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
			Default:  "scep",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		consts.FieldName: {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		consts.FieldDisplayName: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldAuthType: {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		consts.FieldChallenge: {
			Type:     schema.TypeString,
			Optional: true,
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		SchemaVersion: 1,
		CreateContext: scepAuthResourceWrite,
		UpdateContext: scepAuthResourceUpdate,
		ReadContext:   provider.ReadContextWrapper(scepAuthResourceRead),
		DeleteContext: scepAuthResourceDelete,
		Schema:        fields,
	}
}

func scepRoleResourcePath(backend, name string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(name, "/")
}

func scepAuthResourceWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := verifyScepAuthFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := scepRoleResourcePath(backend, name)

	data := map[string]interface{}{}
	updateTokenFields(d, data, true)

	for _, k := range scepAuthStringFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	log.Printf("[DEBUG] Writing %q to SCEP auth backend", path)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("Error writing %q to SCEP auth backend: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote %q to SCEP auth backend", path)

	return scepAuthResourceRead(ctx, d, meta)
}

func verifyScepAuthFeatureSupported(meta any) error {
	currentVersion := meta.(*provider.ProviderMeta).GetVaultVersion()

	minVersion := provider.VaultVersion120
	if !provider.IsAPISupported(meta, minVersion) {
		return fmt.Errorf("feature not enabled on current Vault version. min version required=%s; "+
			"current vault version=%s", minVersion, currentVersion)
	}

	if !provider.IsEnterpriseSupported(meta) {
		return errors.New("feature requires Vault Enterprise")
	}
	return nil
}

func scepAuthResourceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := verifyScepAuthFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	data := map[string]interface{}{}
	updateTokenFields(d, data, true)

	for _, k := range scepAuthStringFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	log.Printf("[DEBUG] Updating %q to SCEP auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("Error updating %q to SCEP auth backend: %s", path, err)
	}
	log.Printf("[DEBUG] Updated %q to SCEP auth backend", path)

	return scepAuthResourceRead(ctx, d, meta)
}

func scepAuthResourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := verifyScepAuthFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Reading SCEP auth %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("Error reading SCEP auth %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read SCEP auth %q", path)

	if resp == nil {
		log.Printf("[WARN] SCEP auth %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	for _, field := range scepAuthStringFields {
		if field == consts.FieldChallenge {
			continue
		}
		d.Set(field, resp.Data[field])
	}

	return checkCIDRs(d, TokenFieldBoundCIDRs)
}

func scepAuthResourceDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting SCEP auth %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("Error deleting SCEP auth %q", path)
	}
	log.Printf("[DEBUG] Deleted SCEP auth %q", path)

	return nil
}
