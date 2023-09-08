// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func certAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"name": {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		"certificate": {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		"allowed_names": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"allowed_common_names": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"allowed_dns_sans": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"allowed_email_sans": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"allowed_uri_sans": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"allowed_organization_units": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			Computed:      true,
			Deprecated:    "Use allowed_organizational_units",
			ConflictsWith: []string{"allowed_organizational_units"},
		},
		"allowed_organizational_units": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			ConflictsWith: []string{"allowed_organization_units"},
		},
		"required_extensions": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"display_name": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"allowed_metadata_extensions": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "A array of oid extensions.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"backend": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
			Default:  "cert",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		SchemaVersion: 1,

		CreateContext: certAuthResourceWrite,
		UpdateContext: certAuthResourceUpdate,
		ReadContext:   provider.ReadContextWrapper(certAuthResourceRead),
		DeleteContext: certAuthResourceDelete,
		Schema:        fields,
	}
}

func certCertResourcePath(backend, name string) string {
	return "auth/" + strings.Trim(backend, "/") + "/certs/" + strings.Trim(name, "/")
}

func certAuthResourceWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := certCertResourcePath(backend, name)

	data := map[string]interface{}{}
	updateTokenFields(d, data, true)

	data["certificate"] = d.Get("certificate")

	if v, ok := d.GetOk("allowed_names"); ok {
		data["allowed_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_common_names"); ok {
		data["allowed_common_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_dns_sans"); ok {
		data["allowed_dns_sans"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_metadata_extensions"); ok {
		data["allowed_metadata_extensions"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_uri_sans"); ok {
		data["allowed_uri_sans"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_organizational_units"); ok {
		data["allowed_organizational_units"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("required_extensions"); ok {
		data["required_extensions"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("display_name"); ok {
		data["display_name"] = v.(string)
	}

	log.Printf("[DEBUG] Writing %q to cert auth backend", path)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("Error writing %q to cert auth backend: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote %q to cert auth backend", path)

	return certAuthResourceRead(ctx, d, meta)
}

func certAuthResourceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	data := map[string]interface{}{}
	updateTokenFields(d, data, false)

	data["certificate"] = d.Get("certificate")

	if v, ok := d.GetOk("allowed_names"); ok {
		data["allowed_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_common_names"); ok {
		data["allowed_common_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_dns_sans"); ok {
		data["allowed_dns_sans"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_uri_sans"); ok {
		data["allowed_uri_sans"] = v.(*schema.Set).List()
	}

	if d.HasChange("allowed_metadata_extensions") {
		data["allowed_metadata_extensions"] = d.Get("allowed_metadata_extensions").(*schema.Set).List()
	}

	if d.HasChange("allowed_organizational_units") {
		data["allowed_organizational_units"] = d.Get("allowed_organizational_units").(*schema.Set).List()
	}

	if v, ok := d.GetOk("required_extensions"); ok {
		data["required_extensions"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("display_name"); ok {
		data["display_name"] = v.(string)
	}

	log.Printf("[DEBUG] Updating %q in cert auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("Error updating %q in cert auth backend: %s", path, err)
	}
	log.Printf("[DEBUG] Updated %q in cert auth backend", path)

	return certAuthResourceRead(ctx, d, meta)
}

func certAuthResourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Reading cert %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("Error reading cert %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read cert %q", path)

	if resp == nil {
		log.Printf("[WARN] cert %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	d.Set("certificate", resp.Data["certificate"])
	d.Set("display_name", resp.Data["display_name"])

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_names"] != nil {
		d.Set("allowed_names",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_names"].([]interface{})))
	} else {
		d.Set("allowed_names",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_dns_sans"] != nil {
		d.Set("allowed_dns_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_dns_sans"].([]interface{})))
	} else {
		d.Set("allowed_dns_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_email_sans"] != nil {
		d.Set("allowed_email_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_email_sans"].([]interface{})))
	} else {
		d.Set("allowed_email_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_uri_sans"] != nil {
		d.Set("allowed_uri_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_uri_sans"].([]interface{})))
	} else {
		d.Set("allowed_uri_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["required_extensions"] != nil {
		d.Set("required_extensions",
			schema.NewSet(
				schema.HashString, resp.Data["required_extensions"].([]interface{})))
	} else {
		d.Set("required_extensions",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_metadata_extensions"] != nil {
		d.Set("allowed_metadata_extensions",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_metadata_extensions"].([]interface{})))
	} else {
		d.Set("allowed_metadata_extensions",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	if err := d.Set("allowed_organizational_units", resp.Data["allowed_organizational_units"]); err != nil {
		return diag.FromErr(err)
	}

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func certAuthResourceDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting cert %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("Error deleting cert %q", path)
	}
	log.Printf("[DEBUG] Deleted cert %q", path)

	return nil
}
