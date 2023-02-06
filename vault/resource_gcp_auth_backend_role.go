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

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	gcpAuthBackendFromPathRegex  = regexp.MustCompile("^auth/(.+)/role/[^/]+$")
	gcpAuthRoleNameFromPathRegex = regexp.MustCompile("^auth/.+/role/([^/]+)$")
)

func gcpAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role": {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		"type": {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		"bound_projects": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			ForceNew: true,
		},
		"add_group_aliases": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"max_jwt_exp": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"allow_gce_inference": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"bound_service_accounts": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"bound_zones": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"bound_regions": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"bound_instance_groups": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"bound_labels": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"backend": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
			Default:  "gcp",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		SchemaVersion: 1,

		CreateContext: gcpAuthResourceCreate,
		UpdateContext: gcpAuthResourceUpdate,
		ReadContext:   ReadContextWrapper(gcpAuthResourceRead),
		DeleteContext: gcpAuthResourceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

func gcpRoleResourcePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func gcpRoleUpdateFields(d *schema.ResourceData, data map[string]interface{}, create bool) {
	updateTokenFields(d, data, create)

	if v, ok := d.GetOk("type"); ok {
		data["type"] = v.(string)
	}

	if v, ok := d.GetOk("bound_projects"); ok {
		data["bound_projects"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("bound_service_accounts"); ok {
		data["bound_service_accounts"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOkExists("add_group_aliases"); ok {
		data["add_group_aliases"] = v.(bool)
	}

	if v, ok := d.GetOk("max_jwt_exp"); ok {
		data["max_jwt_exp"] = v.(string)
	}

	if v, ok := d.GetOkExists("allow_gce_inference"); ok {
		data["allow_gce_inference"] = v.(bool)
	}

	if v, ok := d.GetOk("bound_zones"); ok {
		data["bound_zones"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("bound_regions"); ok {
		data["bound_regions"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("bound_instance_groups"); ok {
		data["bound_instance_groups"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("bound_labels"); ok {
		data["bound_labels"] = v.(*schema.Set).List()
	}
}

func gcpAuthResourceCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := gcpRoleResourcePath(backend, role)

	data := map[string]interface{}{}
	gcpRoleUpdateFields(d, data, true)

	log.Printf("[DEBUG] Writing role %q to GCP auth backend", path)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("Error writing GCP auth role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote role %q to GCP auth backend", path)

	return gcpAuthResourceRead(ctx, d, meta)
}

func gcpAuthResourceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	data := map[string]interface{}{}
	gcpRoleUpdateFields(d, data, false)

	log.Printf("[DEBUG] Updating role %q in GCP auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("Error updating GCP auth role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated role %q to GCP auth backend", path)

	return gcpAuthResourceRead(ctx, d, meta)
}

func gcpAuthResourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Reading GCP role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("Error reading GCP role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read GCP role %q", path)

	if resp == nil {
		log.Printf("[WARN] GCP role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	backend, err := gcpAuthResourceBackendFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for GCP auth backend role: %s", path, err)
	}
	d.Set("backend", backend)
	role, err := gcpAuthResourceRoleFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for GCP auth backend role: %s", path, err)
	}
	d.Set("role", role)

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range []string{"bound_projects", "add_group_aliases", "max_jwt_exp", "bound_service_accounts", "bound_zones", "bound_regions", "bound_instance_groups"} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error reading %s for GCP Auth Backend Role %q: %q", k, path, err)
			}
		}
	}

	if v, ok := resp.Data["bound_labels"]; ok {
		labels := []string{}
		for labelK, labelV := range v.(map[string]interface{}) {
			labels = append(labels, fmt.Sprintf("%s:%s", labelK, labelV))
		}

		if err := d.Set("bound_labels", labels); err != nil {
			return diag.Errorf("error setting bound_labels for GCP auth backend role: %q", err)
		}
	}

	// These checks are done for backwards compatibility. The 'type' key used to be
	// 'role_type' and was changed to 'role' errorneously before being corrected
	if v, ok := resp.Data["type"]; ok {
		d.Set("type", v)
	} else if v, ok := resp.Data["role_type"]; ok {
		d.Set("type", v)
	} else if v, ok := resp.Data["role"]; ok {
		d.Set("type", v)
	}

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func gcpAuthResourceDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting GCP role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("Error deleting GCP role %q", path)
	}
	log.Printf("[DEBUG] Deleted GCP role %q", path)

	return nil
}

func gcpAuthResourceBackendFromPath(path string) (string, error) {
	if !gcpAuthBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := gcpAuthBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func gcpAuthResourceRoleFromPath(path string) (string, error) {
	if !gcpAuthRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := gcpAuthRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}
