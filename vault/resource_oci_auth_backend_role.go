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
	"github.com/hashicorp/terraform-provider-vault/internal/consts"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	ociAuthBackendFromPathRegex  = regexp.MustCompile("^auth/(.+)/role/[^/]+$")
	ociAuthRoleNameFromPathRegex = regexp.MustCompile("^auth/.+/role/([^/]+)$")
)

func ociAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role.",
			ForceNew:    true,
		},
		"ocid_list": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "A list of Group or Dynamic Group OCIDs that can take this role.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"backend": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Unique name of the auth backend to configure.",
			ForceNew:    true,
			Default:     "oci",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		SchemaVersion: 1,

		CreateContext: ociAuthRoleCreate,
		UpdateContext: ociAuthRoleUpdate,
		ReadContext:   provider.ReadContextWrapper(ociAuthRoleRead),
		DeleteContext: ociAuthRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

func ociRoleUpdateFields(d *schema.ResourceData, data map[string]interface{}, create bool) {
	updateTokenFields(d, data, create)

	if _, ok := d.GetOk("ocid_list"); ok {
		iOL := d.Get("ocid_list").([]interface{})
		ocid_list := make([]string, len(iOL))
		for i, iO := range iOL {
			ocid_list[i] = iO.(string)
		}
		data["ocid_list"] = strings.Join(ocid_list, ",")
	}
}

func ociAuthRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := ociRoleResourcePath(backend, name)

	log.Printf("[DEBUG] Writing %s auth backend role %q", consts.AuthMethodOCI, path)

	data := map[string]interface{}{}
	ociRoleUpdateFields(d, data, true)

	log.Printf("[DEBUG] Writing role %q to %s auth backend", path, consts.AuthMethodOCI)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("Error writing %s auth role %q: %s", consts.AuthMethodOCI, path, err)
	}
	log.Printf("[DEBUG] Wrote role %q to %s auth backend", path, consts.AuthMethodOCI)

	return ociAuthRoleRead(ctx, d, meta)
}

func ociAuthRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	data := map[string]interface{}{}
	ociRoleUpdateFields(d, data, false)

	log.Printf("[DEBUG] Updating role %q in %s auth backend", path, consts.AuthMethodOCI)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("Error updating %s auth role %q: %s", consts.AuthMethodOCI, path, err)
	}
	log.Printf("[DEBUG] Updated role %q to %s auth backend", path, consts.AuthMethodOCI)

	return ociAuthRoleRead(ctx, d, meta)
}

func ociAuthRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Reading %s role %q", consts.AuthMethodOCI, path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("Error reading %s role %q: %s", consts.AuthMethodOCI, path, err)
	}
	log.Printf("[DEBUG] Read %s role %q", consts.AuthMethodOCI, path)

	if resp == nil {
		log.Printf("[WARN] %s role %q not found, removing from state", consts.AuthMethodOCI, path)
		d.SetId("")
		return nil
	}

	backend, err := ociAuthResourceBackendFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for %s auth backend role: %s", path, consts.AuthMethodOCI, err)
	}
	d.Set("backend", backend)
	name, err := ociAuthResourceRoleFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for %s auth backend role: %s", path, consts.AuthMethodOCI, err)
	}
	d.Set("name", name)

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range []string{"ocid_list"} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error reading %s for %s Auth Backend Role %q: %q", k, path, consts.AuthMethodOCI, err)
			}
		}
	}

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func ociAuthRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting %s auth backend role %q", consts.AuthMethodOCI, path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting %s auth backend role %q", consts.AuthMethodOCI, path)
	}
	log.Printf("[DEBUG] Deleted %s auth backend role %q", consts.AuthMethodOCI, path)

	return nil
}

func ociRoleResourcePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func ociAuthResourceBackendFromPath(path string) (string, error) {
	if !ociAuthBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := ociAuthBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func ociAuthResourceRoleFromPath(path string) (string, error) {
	if !ociAuthRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := ociAuthRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}
