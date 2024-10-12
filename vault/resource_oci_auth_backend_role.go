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
	ociAuthBackendRoleBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/role/.+$")
	ociAuthBackendRoleNameFromPathRegex    = regexp.MustCompile("^auth/.+/role/(.+)$")
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
		CreateContext: ociAuthBackendRoleCreate,
		ReadContext:   ReadContextWrapper(ociAuthBackendRoleRead),
		UpdateContext: ociAuthBackendRoleUpdate,
		DeleteContext: ociAuthBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

func ociAuthBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := ociAuthBackendRolePath(backend, name)

	log.Printf("[DEBUG] Writing OCI auth backend role %q", path)

	data := map[string]interface{}{}
	updateTokenFields(d, data, true)

	iOL := d.Get("ocid_list").([]interface{})
	ocid_list := make([]string, len(iOL))
	for i, iO := range iOL {
		ocid_list[i] = iO.(string)
	}
	data["ocid_list"] = strings.Join(ocid_list, ",")

	d.SetId(path)
	if _, err := client.Logical().Write(path, data); err != nil {
		d.SetId("")
		return diag.Errorf("error writing OCI auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote OCI auth backend role %q", path)

	return ociAuthBackendRoleRead(ctx, d, meta)
}

func ociAuthBackendRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	backend, err := ociAuthBackendRoleBackendFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for OCI auth backend role: %s", path, err)
	}

	role, err := ociAuthBackendRoleNameFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for OCI auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading OCI auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading OCI auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read OCI auth backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] OCI auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	d.Set("backend", backend)
	d.Set("name", role)
	d.Set("ocid_list", resp.Data["ocid_list"])

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func ociAuthBackendRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Updating OCI auth backend role %q", path)

	data := map[string]interface{}{}
	updateTokenFields(d, data, false)

	iOL := d.Get("ocid_list").([]interface{})
	ocid_list := make([]string, len(iOL))
	for i, iO := range iOL {
		ocid_list[i] = iO.(string)
	}
	data["ocid_list"] = strings.Join(ocid_list, ",")

	log.Printf("[DEBUG] Updating role %q in OCI auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("Error updating OCI auth role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated role %q to OCI auth backend", path)

	return ociAuthBackendRoleRead(ctx, d, meta)
}

func ociAuthBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting OCI auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting OCI auth backend role %q", path)
	}
	log.Printf("[DEBUG] Deleted OCI auth backend role %q", path)

	return nil
}

func ociAuthBackendRolePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func ociAuthBackendRoleNameFromPath(path string) (string, error) {
	if !ociAuthBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := ociAuthBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func ociAuthBackendRoleBackendFromPath(path string) (string, error) {
	if !ociAuthBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := ociAuthBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
