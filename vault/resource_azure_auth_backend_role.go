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
	azureAuthBackendRoleBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/role/.+$")
	azureAuthBackendRoleNameFromPathRegex    = regexp.MustCompile("^auth/.+/role/(.+)$")
)

func azureAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role.",
			ForceNew:    true,
		},
		"bound_service_principal_ids": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "The list of Service Principal IDs that login is restricted to.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_group_ids": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "The list of group ids that login is restricted to.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_locations": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "The list of locations that login is restricted to.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_subscription_ids": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "The list of subscription IDs that login is restricted to.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_resource_groups": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "The list of resource groups that login is restricted to.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_scale_sets": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "The list of scale set names that the login is restricted to.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"backend": {
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
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		CreateContext: azureAuthBackendRoleCreate,
		ReadContext:   provider.ReadContextWrapper(azureAuthBackendRoleRead),
		UpdateContext: azureAuthBackendRoleUpdate,
		DeleteContext: azureAuthBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

func azureAuthBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := azureAuthBackendRolePath(backend, role)

	log.Printf("[DEBUG] Writing Azure auth backend role %q", path)

	data := map[string]interface{}{}
	updateTokenFields(d, data, true)

	if _, ok := d.GetOk("bound_service_principal_ids"); ok {
		iSPI := d.Get("bound_service_principal_ids").([]interface{})
		bound_service_principal_ids := make([]string, len(iSPI))
		for i, iSP := range iSPI {
			bound_service_principal_ids[i] = iSP.(string)
		}
		data["bound_service_principal_ids"] = bound_service_principal_ids
	}

	if _, ok := d.GetOk("bound_group_ids"); ok {
		iGI := d.Get("bound_group_ids").([]interface{})
		bound_group_ids := make([]string, len(iGI))
		for i, iG := range iGI {
			bound_group_ids[i] = iG.(string)
		}
		data["bound_group_ids"] = bound_group_ids
	}

	if _, ok := d.GetOk("bound_locations"); ok {
		iLS := d.Get("bound_locations").([]interface{})
		bound_locations := make([]string, len(iLS))
		for i, iL := range iLS {
			bound_locations[i] = iL.(string)
		}
		data["bound_locations"] = bound_locations
	}

	if _, ok := d.GetOk("bound_subscription_ids"); ok {
		iSI := d.Get("bound_subscription_ids").([]interface{})
		bound_subscription_ids := make([]string, len(iSI))
		for i, iS := range iSI {
			bound_subscription_ids[i] = iS.(string)
		}
		data["bound_subscription_ids"] = bound_subscription_ids
	}

	if _, ok := d.GetOk("bound_resource_groups"); ok {
		iRGN := d.Get("bound_resource_groups").([]interface{})
		bound_resource_groups := make([]string, len(iRGN))
		for i, iRG := range iRGN {
			bound_resource_groups[i] = iRG.(string)
		}
		data["bound_resource_groups"] = bound_resource_groups
	}

	if _, ok := d.GetOk("bound_scale_sets"); ok {
		iSS := d.Get("bound_scale_sets").([]interface{})
		bound_scale_sets := make([]string, len(iSS))
		for i, iS := range iSS {
			bound_scale_sets[i] = iS.(string)
		}
		data["bound_scale_sets"] = bound_scale_sets
	}

	d.SetId(path)
	if _, err := client.Logical().Write(path, data); err != nil {
		d.SetId("")
		return diag.Errorf("error writing Azure auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Azure auth backend role %q", path)

	return azureAuthBackendRoleRead(ctx, d, meta)
}

func azureAuthBackendRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	backend, err := azureAuthBackendRoleBackendFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for Azure auth backend role: %s", path, err)
	}

	role, err := azureAuthBackendRoleNameFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for Azure auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading Azure auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading Azure auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Azure auth backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] Azure auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	d.Set("backend", backend)
	d.Set("role", role)
	d.Set("bound_service_principal_ids", resp.Data["bound_service_principal_ids"])
	d.Set("bound_group_ids", resp.Data["bound_group_ids"])
	d.Set("bound_locations", resp.Data["bound_locations"])
	d.Set("bound_subscription_ids", resp.Data["bound_subscription_ids"])
	d.Set("bound_resource_groups", resp.Data["bound_resource_groups"])
	d.Set("bound_scale_sets", resp.Data["bound_scale_sets"])

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func azureAuthBackendRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Updating Azure auth backend role %q", path)

	data := map[string]interface{}{}
	updateTokenFields(d, data, false)

	if _, ok := d.GetOk("bound_service_principal_ids"); ok {
		iSPI := d.Get("bound_service_principal_ids").([]interface{})
		bound_service_principal_ids := make([]string, len(iSPI))
		for i, iSP := range iSPI {
			bound_service_principal_ids[i] = iSP.(string)
		}
		data["bound_service_principal_ids"] = bound_service_principal_ids
	}
	if _, ok := d.GetOk("bound_group_ids"); ok {
		iGI := d.Get("bound_group_ids").([]interface{})
		bound_group_ids := make([]string, len(iGI))
		for i, iG := range iGI {
			bound_group_ids[i] = iG.(string)
		}
		data["bound_group_ids"] = bound_group_ids
	}
	if _, ok := d.GetOk("bound_locations"); ok {
		iLS := d.Get("bound_locations").([]interface{})
		bound_locations := make([]string, len(iLS))
		for i, iL := range iLS {
			bound_locations[i] = iL.(string)
		}
		data["bound_locations"] = bound_locations
	}
	if _, ok := d.GetOk("bound_subscription_ids"); ok {
		iSI := d.Get("bound_subscription_ids").([]interface{})
		bound_subscription_ids := make([]string, len(iSI))
		for i, iS := range iSI {
			bound_subscription_ids[i] = iS.(string)
		}
		data["bound_subscription_ids"] = bound_subscription_ids
	}
	if _, ok := d.GetOk("bound_resource_groups"); ok {
		iRGN := d.Get("bound_resource_groups").([]interface{})
		bound_resource_groups := make([]string, len(iRGN))
		for i, iRG := range iRGN {
			bound_resource_groups[i] = iRG.(string)
		}
		data["bound_resource_groups"] = bound_resource_groups
	}
	if _, ok := d.GetOk("bound_scale_sets"); ok {
		iSS := d.Get("bound_scale_sets").([]interface{})
		bound_scale_sets := make([]string, len(iSS))
		for i, iS := range iSS {
			bound_scale_sets[i] = iS.(string)
		}
		data["bound_scale_sets"] = bound_scale_sets
	}
	log.Printf("[DEBUG] Updating role %q in Azure auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("Error updating Azure auth role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated role %q to Azure auth backend", path)

	return azureAuthBackendRoleRead(ctx, d, meta)
}

func azureAuthBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting Azure auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting Azure auth backend role %q", path)
	}
	log.Printf("[DEBUG] Deleted Azure auth backend role %q", path)

	return nil
}

func azureAuthBackendRolePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func azureAuthBackendRoleNameFromPath(path string) (string, error) {
	if !azureAuthBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := azureAuthBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func azureAuthBackendRoleBackendFromPath(path string) (string, error) {
	if !azureAuthBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := azureAuthBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
