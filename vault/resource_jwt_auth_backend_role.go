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
	"github.com/hashicorp/terraform-provider-vault/util"
)

var (
	jwtAuthBackendRoleBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/role/.+$")
	jwtAuthBackendRoleNameFromPathRegex    = regexp.MustCompile("^auth/.+/role/(.+)$")
)

func jwtAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role_name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role.",
			ForceNew:    true,
		},
		"role_type": {
			Type:        schema.TypeString,
			Description: "Type of role, either \"oidc\" (default) or \"jwt\"",
			Optional:    true,
			Computed:    true,
			ForceNew:    true,
		},
		"bound_audiences": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of aud claims to match against. Any match is sufficient.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"user_claim": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The claim to use to uniquely identify the user; this will be used as the name for the Identity entity alias created due to a successful login.",
		},
		"clock_skew_leeway": {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     0,
			Description: "The amount of leeway to add to all claims to account for clock skew, in seconds. Defaults to 60 seconds if set to 0 and can be disabled if set to -1. Only applicable with 'jwt' roles.",
		},
		"expiration_leeway": {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     0,
			Description: "The amount of leeway to add to expiration (exp) claims to account for clock skew, in seconds. Defaults to 60 seconds if set to 0 and can be disabled if set to -1. Only applicable with 'jwt' roles.",
		},
		"not_before_leeway": {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     0,
			Description: "The amount of leeway to add to not before (nbf) claims to account for clock skew, in seconds. Defaults to 150 seconds if set to 0 and can be disabled if set to -1. Only applicable with 'jwt' roles. ",
		},
		"allowed_redirect_uris": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Description: "The list of allowed values for redirect_uri during OIDC logins.",
		},
		"bound_subject": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "If set, requires that the sub claim matches this value.",
		},
		"oidc_scopes": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of OIDC scopes to be used with an OIDC role. The standard scope \"openid\" is automatically included and need not be specified.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_claims_type": {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "How to interpret values in the claims/values map: can be either \"string\" (exact match) or \"glob\" (wildcard match).",
		},
		"bound_claims": {
			Type:        schema.TypeMap,
			Optional:    true,
			Description: "Map of claims/values to match against. The expected value may be a single string or a comma-separated string list.",
		},
		"disable_bound_claims_parsing": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Disable bound claim value parsing. Useful when values contain commas.",
		},
		"claim_mappings": {
			Type:        schema.TypeMap,
			Optional:    true,
			Description: "Map of claims (keys) to be copied to specified metadata fields (values).",
		},
		"groups_claim": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The claim to use to uniquely identify the set of groups to which the user belongs; this will be used as the names for the Identity group aliases created due to a successful login. The claim value must be a list of strings.",
		},
		"verbose_oidc_logging": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Log received OIDC tokens and claims when debug-level logging is active. Not recommended in production since sensitive information may be present in OIDC responses.",
		},
		"user_claim_json_pointer": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Specifies if the user_claim value uses JSON pointer syntax for referencing claims. By default, the user_claim value will not use JSON pointer.",
		},
		"max_age": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "Specifies the allowable elapsed time in seconds since the last time the user was actively authenticated.",
		},
		"backend": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Unique name of the auth backend to configure.",
			ForceNew:    true,
			Default:     "jwt",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		CreateContext: jwtAuthBackendRoleCreate,
		ReadContext:   provider.ReadContextWrapper(jwtAuthBackendRoleRead),
		UpdateContext: jwtAuthBackendRoleUpdate,
		DeleteContext: jwtAuthBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

func jwtAuthBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	role := d.Get("role_name").(string)
	path := jwtAuthBackendRolePath(backend, role)

	log.Printf("[DEBUG] Writing JWT auth backend role %q", path)
	data := jwtAuthBackendRoleDataToWrite(d, true)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error writing JWT auth backend role %q: %s", path, err)
	}
	d.SetId(path)
	log.Printf("[DEBUG] Wrote JWT auth backend role %q", path)

	if v, ok := d.GetOk("role_id"); ok {
		log.Printf("[DEBUG] Writing JWT auth backend role %q RoleID", path)
		_, err := client.Logical().Write(path+"/role-id", map[string]interface{}{
			"role_id": v.(string),
		})
		if err != nil {
			return diag.Errorf("error writing JWT auth backend role %q's RoleID: %s", path, err)
		}
		log.Printf("[DEBUG] Wrote JWT auth backend role %q RoleID", path)
	}

	return jwtAuthBackendRoleRead(ctx, d, meta)
}

func jwtAuthBackendRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	backend, err := jwtAuthBackendRoleBackendFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for JWT auth backend role: %s", path, err)
	}

	role, err := jwtAuthBackendRoleNameFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for JWT auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading JWT auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading JWT auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read JWT auth backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] JWT auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	if resp.Data["bound_audiences"] != nil {
		boundAuds := util.JsonStringArrayToStringArray(resp.Data["bound_audiences"].([]interface{}))
		err = d.Set("bound_audiences", boundAuds)
		if err != nil {
			return diag.Errorf("error setting bound_audiences in state: %s", err)
		}
	} else {
		d.Set("bound_audiences", make([]string, 0))
	}

	d.Set("user_claim", resp.Data["user_claim"].(string))

	if resp.Data["allowed_redirect_uris"] != nil {
		allowedRedirectUris := util.JsonStringArrayToStringArray(resp.Data["allowed_redirect_uris"].([]interface{}))
		err = d.Set("allowed_redirect_uris", allowedRedirectUris)
		if err != nil {
			return diag.Errorf("error setting allowed_redirect_uris in state: %s", err)
		}
	}

	d.Set("role_type", resp.Data["role_type"].(string))
	d.Set("bound_subject", resp.Data["bound_subject"].(string))

	if resp.Data["oidc_scopes"] != nil {
		cidrs := util.JsonStringArrayToStringArray(resp.Data["oidc_scopes"].([]interface{}))
		err = d.Set("oidc_scopes", cidrs)
		if err != nil {
			return diag.Errorf("error setting oidc_scopes in state: %s", err)
		}
	} else {
		d.Set("oidc_scopes", make([]string, 0))
	}

	if v, ok := resp.Data["bound_claims_type"]; ok {
		d.Set("bound_claims_type", v)
	}

	if resp.Data["bound_claims"] != nil {
		boundClaims := make(map[string]interface{})
		respBoundClaims := resp.Data["bound_claims"].(map[string]interface{})
		for k, v := range respBoundClaims {
			switch boundClaimVal := v.(type) {
			case []interface{}:
				boundClaims[k] = strings.Join(util.JsonStringArrayToStringArray(boundClaimVal), ",")
			case string:
				boundClaims[k] = boundClaimVal
			default:
				return diag.Errorf("bound claim is not a string or list: %v", v)
			}
		}
		d.Set("bound_claims", boundClaims)
	}

	if resp.Data["claim_mappings"] != nil {
		d.Set("claim_mappings", resp.Data["claim_mappings"])
	}

	d.Set("groups_claim", resp.Data["groups_claim"].(string))

	if v, ok := resp.Data["clock_skew_leeway"]; ok {
		d.Set("clock_skew_leeway", v)
	}
	if v, ok := resp.Data["expiration_leeway"]; ok {
		d.Set("expiration_leeway", v)
	}
	if v, ok := resp.Data["not_before_leeway"]; ok {
		d.Set("not_before_leeway", v)
	}
	if v, ok := resp.Data["verbose_oidc_logging"]; ok {
		d.Set("verbose_oidc_logging", v)
	}
	if v, ok := resp.Data["user_claim_json_pointer"]; ok {
		d.Set("user_claim_json_pointer", v)
	}
	if v, ok := resp.Data["max_age"]; ok {
		d.Set("max_age", v)
	}

	d.Set("backend", backend)
	d.Set("role_name", role)

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func jwtAuthBackendRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Updating JWT auth backend role %q", path)
	data := jwtAuthBackendRoleDataToWrite(d, false)
	_, err := client.Logical().Write(path, data)

	d.SetId(path)

	if err != nil {
		return diag.Errorf("error updating JWT auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated JWT auth backend role %q", path)

	if d.HasChange("role_id") {
		log.Printf("[DEBUG] Updating JWT auth backend role %q RoleID", path)
		_, err := client.Logical().Write(path+"/role-id", map[string]interface{}{
			"role_id": d.Get("role_id").(string),
		})
		if err != nil {
			return diag.Errorf("error updating JWT auth backend role %q's RoleID: %s", path, err)
		}
		log.Printf("[DEBUG] Updated JWT auth backend role %q RoleID", path)
	}

	return jwtAuthBackendRoleRead(ctx, d, meta)
}

func jwtAuthBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting JWT auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil && !util.Is404(err) {
		return diag.Errorf("error deleting JWT auth backend role %q", path)
	} else if err != nil {
		log.Printf("[DEBUG] JWT auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted JWT auth backend role %q", path)

	return nil
}

func jwtAuthBackendRolePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func jwtAuthBackendRoleNameFromPath(path string) (string, error) {
	if !jwtAuthBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := jwtAuthBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func jwtAuthBackendRoleBackendFromPath(path string) (string, error) {
	if !jwtAuthBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := jwtAuthBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func jwtAuthBackendRoleDataToWrite(d *schema.ResourceData, create bool) map[string]interface{} {
	data := map[string]interface{}{}

	updateTokenFields(d, data, create)

	data["bound_audiences"] = util.TerraformSetToStringArray(d.Get("bound_audiences"))
	data["user_claim"] = d.Get("user_claim")
	data["user_claim_json_pointer"] = d.Get("user_claim_json_pointer")

	if v, ok := d.GetOk("max_age"); ok {
		data["max_age"] = v
	}

	if dataList := util.TerraformSetToStringArray(d.Get("allowed_redirect_uris")); len(dataList) > 0 {
		data["allowed_redirect_uris"] = dataList
	}

	if v, ok := d.GetOk("role_type"); ok {
		data["role_type"] = v.(string)
	}

	if v, ok := d.GetOkExists("bound_subject"); ok {
		data["bound_subject"] = v.(string)
	}

	if dataList := util.TerraformSetToStringArray(d.Get("oidc_scopes")); len(dataList) > 0 {
		data["oidc_scopes"] = dataList
	}

	if v, ok := d.GetOkExists("bound_claims_type"); ok {
		data["bound_claims_type"] = v.(string)
	}

	boundClaims := make(map[string]interface{})
	if v, ok := d.GetOk("bound_claims"); ok {
		var disableParseClaims bool
		if v, ok := d.GetOkExists("disable_bound_claims_parsing"); ok {
			disableParseClaims = v.(bool)
		}

		for key, val := range v.(map[string]interface{}) {
			var claims string
			if !disableParseClaims {
				for _, v := range strings.Split(val.(string), ",") {
					claims = claims + strings.TrimSpace(v)
				}
			} else {
				claims = claims + strings.TrimSpace(val.(string))
			}
			boundClaims[key] = claims
		}
	}
	data["bound_claims"] = boundClaims

	if v, ok := d.GetOk("claim_mappings"); ok {
		data["claim_mappings"] = v
	}

	if v, ok := d.GetOkExists("groups_claim"); ok {
		data["groups_claim"] = v.(string)
	}

	data["clock_skew_leeway"] = d.Get("clock_skew_leeway").(int)
	data["expiration_leeway"] = d.Get("expiration_leeway").(int)
	data["not_before_leeway"] = d.Get("not_before_leeway").(int)

	data["verbose_oidc_logging"] = d.Get("verbose_oidc_logging").(bool)

	return data
}
