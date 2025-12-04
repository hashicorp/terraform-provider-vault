// Copyright IBM Corp. 2016, 2025
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

var tokenAuthBackendRoleNameFromPathRegex = regexp.MustCompile("^auth/token/roles/(.+)$")

func tokenAuthBackendRoleEmptyStringSet() (interface{}, error) {
	return []string{}, nil
}

func tokenAuthBackendRoleTokenConfig() *addTokenFieldsConfig {
	return &addTokenFieldsConfig{
		TokenPeriodConflict: []string{"token_ttl"},
		TokenTTLConflict:    []string{"token_period"},

		TokenTypeDefault: "default-service",
	}
}

func tokenAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role_name": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Name of the role.",
		},
		"allowed_policies": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			DefaultFunc: tokenAuthBackendRoleEmptyStringSet,
			Description: "List of allowed policies for given role.",
		},
		"allowed_policies_glob": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			DefaultFunc: tokenAuthBackendRoleEmptyStringSet,
			Description: "Set of allowed policies with glob match for given role.",
		},
		"disallowed_policies": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			DefaultFunc: tokenAuthBackendRoleEmptyStringSet,
			Description: "List of disallowed policies for given role.",
		},
		"disallowed_policies_glob": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			DefaultFunc: tokenAuthBackendRoleEmptyStringSet,
			Description: "Set of disallowed policies with glob match for given role.",
		},
		"orphan": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "If true, tokens created against this policy will be orphan tokens.",
		},
		"allowed_entity_aliases": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			DefaultFunc: tokenAuthBackendRoleEmptyStringSet,
			Description: "Set of allowed entity aliases for this role.",
		},

		"renewable": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "Whether to disable the ability of the token to be renewed past its initial TTL.",
		},
		"path_suffix": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "Tokens created against this role will have the given suffix as part of their path in addition to the role name.",
		},
	}

	addTokenFields(fields, tokenAuthBackendRoleTokenConfig())

	return &schema.Resource{
		CreateContext: tokenAuthBackendRoleCreate,
		ReadContext:   provider.ReadContextWrapper(tokenAuthBackendRoleRead),
		UpdateContext: tokenAuthBackendRoleUpdate,
		DeleteContext: tokenAuthBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

func tokenAuthBackendRoleUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	setTokenFields(d, data, tokenAuthBackendRoleTokenConfig())

	data["allowed_policies"] = d.Get("allowed_policies").(*schema.Set).List()
	data["allowed_policies_glob"] = d.Get("allowed_policies_glob").(*schema.Set).List()
	data["disallowed_policies"] = d.Get("disallowed_policies").(*schema.Set).List()
	data["disallowed_policies_glob"] = d.Get("disallowed_policies_glob").(*schema.Set).List()
	data["orphan"] = d.Get("orphan").(bool)
	data["allowed_entity_aliases"] = d.Get("allowed_entity_aliases").(*schema.Set).List()
	data["renewable"] = d.Get("renewable").(bool)
	data["path_suffix"] = d.Get("path_suffix").(string)
	data["token_type"] = d.Get("token_type").(string)
}

func tokenAuthBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	role := d.Get("role_name").(string)

	path := tokenAuthBackendRolePath(role)

	log.Printf("[DEBUG] Writing Token auth backend role %q", path)

	data := map[string]interface{}{}
	tokenAuthBackendRoleUpdateFields(d, data)

	d.SetId(path)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("Error writing Token auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Token auth backend role %q", path)

	return tokenAuthBackendRoleRead(ctx, d, meta)
}

func tokenAuthBackendRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	roleName, err := tokenAuthBackendRoleNameFromPath(path)
	if err != nil {
		return diag.Errorf("Invalid path %q for Token auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading Token auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("Error reading Token auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Token auth backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] Token auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	d.Set("role_name", roleName)

	params := []string{
		"allowed_policies", "allowed_policies_glob", "disallowed_policies",
		"disallowed_policies_glob", "allowed_entity_aliases", "orphan",
		"path_suffix", "renewable",
	}
	for _, k := range params {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error reading %s for Token auth backend role %q: %q", k, path, err)
		}
	}

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func tokenAuthBackendRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Updating Token auth backend role %q", path)

	data := map[string]interface{}{}
	tokenAuthBackendRoleUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error updating Token auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated Token auth backend role %q", path)

	return tokenAuthBackendRoleRead(ctx, d, meta)
}

func tokenAuthBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting Token auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting Token auth backend role %q", path)
	}
	log.Printf("[DEBUG] Deleted Token auth backend role %q", path)

	return nil
}

func tokenAuthBackendRolePath(role string) string {
	return "auth/token/roles/" + strings.Trim(role, "/")
}

func tokenAuthBackendRoleNameFromPath(path string) (string, error) {
	if !tokenAuthBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := tokenAuthBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}
