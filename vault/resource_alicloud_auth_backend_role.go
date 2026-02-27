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

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func alicloudAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Name of the role. Must correspond with the name of the role reflected in the arn.",
		},
		"arn": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The role's arn.",
		},
		"backend": {
			Type:        schema.TypeString,
			Optional:    true,
			ForceNew:    true,
			Default:     "alicloud",
			Description: "Auth backend.",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		CreateContext: alicloudAuthBackendRoleCreate,
		UpdateContext: alicloudAuthBackendRoleUpdate,
		ReadContext:   provider.ReadContextWrapper(alicloudAuthBackendRoleRead),
		DeleteContext: alicloudAuthBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

func alicloudAuthBackendRolePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func alicloudAuthBackendFromPath(path string) (string, error) {
	parts := strings.Split(path, "/")
	if len(parts) != 4 {
		return "", fmt.Errorf("expected 4 parts in path '%s'", path)
	}
	return parts[1], nil
}

func alicloudAuthRoleFromPath(path string) (string, error) {
	parts := strings.Split(path, "/")
	if len(parts) != 4 {
		return "", fmt.Errorf("expected 4 parts in path '%s'", path)
	}
	return parts[3], nil
}

func alicloudAuthBackendRoleUpdateFields(d *schema.ResourceData, data map[string]interface{}, create bool) {
	updateTokenFields(d, data, create)

	if v, ok := d.GetOk("role"); ok {
		data["role"] = v
	}

	if v, ok := d.GetOk("arn"); ok {
		data["arn"] = v
	}
}

func alicloudAuthBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := alicloudAuthBackendRolePath(backend, role)

	data := map[string]interface{}{}
	alicloudAuthBackendRoleUpdateFields(d, data, true)

	log.Printf("[DEBUG] Writing role %q to AliCloud auth backend", path)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("error writing AliCloud auth role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote role %q to AliCloud auth backend", path)

	return alicloudAuthBackendRoleRead(ctx, d, meta)
}

func alicloudAuthBackendRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	data := map[string]interface{}{}
	alicloudAuthBackendRoleUpdateFields(d, data, false)

	log.Printf("[DEBUG] Updating role %q in AliCloud auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error updating AliCloud auth role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated role %q to AliCloud auth backend", path)

	return alicloudAuthBackendRoleRead(ctx, d, meta)
}

func alicloudAuthBackendRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading AliCloud role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading AliCloud role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read AliCloud role %q", path)

	if resp == nil {
		log.Printf("[WARN] AliCloud role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	backend, err := alicloudAuthBackendFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for AliCloud auth backend role: %s", path, err)
	}
	d.Set("backend", backend)
	role, err := alicloudAuthRoleFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for AliCloud auth backend role: %s", path, err)
	}
	d.Set("role", role)

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range []string{"arn"} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error reading %s for AliCloud Auth Backend Role %q: %q", k, path, err)
			}
		}
	}

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func alicloudAuthBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting AliCloud role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting AliCloud role %q", path)
	}
	log.Printf("[DEBUG] Deleted AliCloud role %q", path)

	return nil
}
