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
	tencentCloudAuthBackendRoleBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/role/.+$")
	tencentCloudAuthBackendRoleNameFromPathRegex    = regexp.MustCompile("^auth/.+/role/(.+)$")
)

func tencentCloudAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role. Must correspond with the name of the role reflected in the arn.",
			ForceNew:    true,
		},
		"arn": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Arn of the above role.",
			ForceNew:    true,
		},
		"backend": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Unique name of the auth backend to configure.",
			ForceNew:    true,
			Default:     "tencentcloud",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"token_ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "The incremental lifetime for generated tokens. This current value of this will be referenced at renewal time.",
		},
		"token_max_ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "The maximum lifetime for generated tokens. This current value of this will be referenced at renewal time.",
		},
		"token_policies": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of policies to encode onto generated tokens. Depending on the auth method, this list may be supplemented by user/group/other values.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"token_bound_cidrs": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of CIDR blocks; if set, specifies blocks of IP addresses which can authenticate successfully, and ties the resulting token to these blocks as well.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"token_explicit_max_ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "If set, will encode an explicit max TTL onto the token. This is a hard cap even if token_ttl and token_max_ttl would otherwise allow a renewal.",
		},
		"token_no_default_policy": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "If set, the default policy will not be set on generated tokens; otherwise it will be added to the policies set in token_policies.",
		},
		"token_num_uses": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "The maximum number of times a generated token may be used (within its lifetime); 0 means unlimited. If you require the token to have the ability to create child tokens, you will need to set this value to 0.",
		},
		"token_period": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "The period, if any, to set on the token.",
		},
		"token_type": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The type of token that should be generated. Can be service, batch, or default to use the mount's tuned default (which unless changed will be service tokens). For token store roles, there are two additional possibilities: default-service and default-batch which specify the type to return unless the client requests a different type at generation time.",
		},
	}

	return &schema.Resource{
		CreateContext: tencentCloudAuthBackendRoleCreate,
		ReadContext:   provider.ReadContextWrapper(tencentCloudAuthBackendRoleRead),
		UpdateContext: tencentCloudAuthBackendRoleUpdate,
		DeleteContext: tencentCloudAuthBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

func tencentCloudAuthBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := tencentCloudAuthBackendRolePath(backend, role)

	log.Printf("[DEBUG] Writing Tencent Cloud auth backend role %q", path)

	arn := d.Get("arn").(string)
	data := map[string]interface{}{
		"arn": arn,
	}

	if v, ok := d.GetOk("token_ttl"); ok {
		data["token_ttl"] = v.(int)
	}
	if v, ok := d.GetOk("token_max_ttl"); ok {
		data["token_max_ttl"] = v.(int)
	}
	if v, ok := d.GetOk("token_policies"); ok {
		data["token_policies"] = v.(*schema.Set).List()
	}
	if v, ok := d.GetOk("token_bound_cidrs"); ok {
		data["token_bound_cidrs"] = v.(*schema.Set).List()
	}
	if v, ok := d.GetOkExists("token_explicit_max_ttl"); ok {
		data["token_explicit_max_ttl"] = v.(int)
	}
	if v, ok := d.GetOkExists("token_no_default_policy"); ok {
		data["token_no_default_policy"] = v.(bool)
	}
	if v, ok := d.GetOkExists("token_num_uses"); ok {
		data["token_num_uses"] = v.(int)
	}
	if v, ok := d.GetOkExists("token_period"); ok {
		data["token_period"] = v.(int)
	}
	if v, ok := d.GetOk("token_type"); ok {
		data["token_type"] = v.(string)
	}

	d.SetId(path)
	if _, err := client.Logical().Write(path, data); err != nil {
		d.SetId("")
		return diag.Errorf("error writing Tencent Cloud auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Tencent Cloud auth backend role %q", path)

	return tencentCloudAuthBackendRoleRead(ctx, d, meta)
}

func tencentCloudAuthBackendRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	backend, err := tencentCloudAuthBackendRoleBackendFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for Tencent Cloud auth backend role: %s", path, err)
	}

	role, err := tencentCloudAuthBackendRoleNameFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for Tencent Cloud auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading Tencent Cloud auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading Tencent Cloud auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Tencent Cloud auth backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] Tencent Cloud auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	_ = d.Set("backend", backend)
	_ = d.Set("role", role)
	_ = d.Set("arn", resp.Data["arn"])

	if v, ok := resp.Data["token_ttl"]; ok {
		_ = d.Set("token_ttl", v)
	}

	if v, ok := resp.Data["token_max_ttl"]; ok {
		_ = d.Set("token_max_ttl", v)
	}

	if v, ok := resp.Data["token_policies"]; ok {
		_ = d.Set("token_policies", v)
	}

	if v, ok := resp.Data["token_bound_cidrs"]; ok {
		_ = d.Set("token_bound_cidrs", v)
	}

	if v, ok := resp.Data["token_explicit_max_ttl"]; ok {
		_ = d.Set("token_explicit_max_ttl", v)
	}

	if v, ok := resp.Data["token_no_default_policy"]; ok {
		_ = d.Set("token_no_default_policy", v)
	}

	if v, ok := resp.Data["token_num_uses"]; ok {
		_ = d.Set("token_num_uses", v)
	}

	if v, ok := resp.Data["token_period"]; ok {
		_ = d.Set("token_period", v)
	}

	if v, ok := resp.Data["token_type"]; ok {
		_ = d.Set("token_type", v)
	}

	return nil
}

func tencentCloudAuthBackendRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Updating Tencent Cloud auth backend role %q", path)

	arn := d.Get("arn").(string)
	data := map[string]interface{}{
		"arn": arn,
	}

	if v, ok := d.GetOk("token_ttl"); ok {
		data["token_ttl"] = v.(int)
	}
	if v, ok := d.GetOk("token_max_ttl"); ok {
		data["token_max_ttl"] = v.(int)
	}
	if v, ok := d.GetOk("token_policies"); ok {
		data["token_policies"] = v.(*schema.Set).List()
	}
	if v, ok := d.GetOk("token_bound_cidrs"); ok {
		data["token_bound_cidrs"] = v.(*schema.Set).List()
	}
	if v, ok := d.GetOkExists("token_explicit_max_ttl"); ok {
		data["token_explicit_max_ttl"] = v.(int)
	}
	if v, ok := d.GetOkExists("token_no_default_policy"); ok {
		data["token_no_default_policy"] = v.(bool)
	}
	if v, ok := d.GetOkExists("token_num_uses"); ok {
		data["token_num_uses"] = v.(int)
	}
	if v, ok := d.GetOkExists("token_period"); ok {
		data["token_period"] = v.(int)
	}
	if v, ok := d.GetOk("token_type"); ok {
		data["token_type"] = v.(string)
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error updating Tencent Cloud auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated Tencent Cloud auth backend role %q", path)

	return tencentCloudAuthBackendRoleRead(ctx, d, meta)
}

func tencentCloudAuthBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting Tencent Cloud auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting Tencent Cloud auth backend role %q", path)
	}
	log.Printf("[DEBUG] Deleted Tencent Cloud auth backend role %q", path)

	return nil
}

func tencentCloudAuthBackendRolePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func tencentCloudAuthBackendRoleNameFromPath(path string) (string, error) {
	if !tencentCloudAuthBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := tencentCloudAuthBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func tencentCloudAuthBackendRoleBackendFromPath(path string) (string, error) {
	if !tencentCloudAuthBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := tencentCloudAuthBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
