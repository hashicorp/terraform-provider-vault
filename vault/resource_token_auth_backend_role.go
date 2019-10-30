package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	tokenAuthBackendRoleNameFromPathRegex = regexp.MustCompile("^auth/token/roles/(.+)$")
)

func tokenAuthBackendRoleEmptyStringSet() (interface{}, error) {
	return []string{}, nil
}

func tokenAuthBackendRoleTokenConfig() *addTokenFieldsConfig {
	return &addTokenFieldsConfig{
		TokenBoundCidrsConflict:     []string{"bound_cidrs"},
		TokenExplicitMaxTTLConflict: []string{"explicit_max_ttl"},
		TokenPeriodConflict:         []string{"period", "token_ttl"},
		TokenTTLConflict:            []string{"period", "token_period"},

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
		"disallowed_policies": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			DefaultFunc: tokenAuthBackendRoleEmptyStringSet,
			Description: "List of disallowed policies for given role.",
		},
		"orphan": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "If true, tokens created against this policy will be orphan tokens.",
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

		// Deprecated
		"period": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Number of seconds to set the TTL to for issued tokens upon renewal. Makes the token a periodic token, which will never expire as long as it is renewed before the TTL each period.",
			ConflictsWith: []string{"token_period", "token_ttl"},
			Deprecated:    "use `token_period` instead if you are running Vault >= 1.2",
		},
		"explicit_max_ttl": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Number of seconds after which issued tokens can no longer be renewed.",
			Deprecated:    "use `token_explicit_max_ttl` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_explicit_max_ttl"},
		},
		"bound_cidrs": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of CIDRs valid as the source address for login requests. This value is also encoded into any resulting token.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Deprecated:    "use `token_bound_cidrs` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_bound_cidrs"},
		},
	}

	addTokenFields(fields, tokenAuthBackendRoleTokenConfig())

	return &schema.Resource{
		Create: tokenAuthBackendRoleCreate,
		Read:   tokenAuthBackendRoleRead,
		Update: tokenAuthBackendRoleUpdate,
		Delete: tokenAuthBackendRoleDelete,
		Exists: tokenAuthBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func tokenAuthBackendRoleUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	setTokenFields(d, data, tokenAuthBackendRoleTokenConfig())

	data["allowed_policies"] = d.Get("allowed_policies").(*schema.Set).List()
	data["disallowed_policies"] = d.Get("disallowed_policies").(*schema.Set).List()
	data["orphan"] = d.Get("orphan").(bool)
	data["renewable"] = d.Get("renewable").(bool)
	data["path_suffix"] = d.Get("path_suffix").(string)
	data["token_type"] = d.Get("token_type").(string)

	// Deprecated
	if v, ok := d.GetOk("period"); ok {
		data["period"] = v.(string)
	}
	if v, ok := d.GetOk("explicit_max_ttl"); ok {
		data["explicit_max_ttl"] = v.(string)
	}
	if v, ok := d.GetOk("bound_cidrs"); ok {
		data["bound_cidrs"] = v.(*schema.Set).List()
	}
}

func tokenAuthBackendRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	role := d.Get("role_name").(string)

	path := tokenAuthBackendRolePath(role)

	log.Printf("[DEBUG] Writing Token auth backend role %q", path)

	data := map[string]interface{}{}
	tokenAuthBackendRoleUpdateFields(d, data)

	d.SetId(path)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error writing Token auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Token auth backend role %q", path)

	return tokenAuthBackendRoleRead(d, meta)
}

func tokenAuthBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	roleName, err := tokenAuthBackendRoleNameFromPath(path)
	if err != nil {
		return fmt.Errorf("Invalid path %q for Token auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading Token auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("Error reading Token auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Token auth backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] Token auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	readTokenFields(d, resp)

	d.Set("role_name", roleName)

	// Check if the user is using the deprecated `period`
	if _, deprecated := d.GetOk("period"); deprecated {
		// Then we see if `token_period` was set and unset it
		// Vault will still return `period`
		if _, ok := d.GetOk("token_period"); ok {
			d.Set("token_period", nil)
		}

		if v, ok := resp.Data["period"]; ok {
			d.Set("period", v)
		}
	}

	// Check if the user is using the deprecated `period`
	if _, deprecated := d.GetOk("explicit_max_ttl"); deprecated {
		// Then we see if `token_explicit_max_ttl` was set and unset it
		// Vault will still return `explicit_max_ttl`
		if _, ok := d.GetOk("token_explicit_max_ttl"); ok {
			d.Set("token_explicit_max_ttl", nil)
		}

		if v, ok := resp.Data["explicit_max_ttl"]; ok {
			d.Set("explicit_max_ttl", v)
		}
	}

	// Check if the user is using the deprecated `bound_cidrs`
	if _, deprecated := d.GetOk("bound_cidrs"); deprecated {
		// Then we see if `token_bound_cidrs` was set and unset it
		// Vault will still return `bound_cidrs`
		if _, ok := d.GetOk("token_bound_cidrs"); ok {
			d.Set("token_bound_cidrs", nil)
		}

		if v, ok := resp.Data["bound_cidrs"]; ok {
			d.Set("bound_cidrs", v)
		}
	}

	for _, k := range []string{"allowed_policies", "disallowed_policies", "orphan", "path_suffix", "renewable"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error reading %s for Token auth backend role %q: %q", k, path, err)
		}
	}

	return nil
}

func tokenAuthBackendRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Updating Token auth backend role %q", path)

	data := map[string]interface{}{}
	tokenAuthBackendRoleUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating Token auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated Token auth backend role %q", path)

	return tokenAuthBackendRoleRead(d, meta)
}

func tokenAuthBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting Token auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting Token auth backend role %q", path)
	}
	log.Printf("[DEBUG] Deleted Token auth backend role %q", path)

	return nil
}

func tokenAuthBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if Token auth backend role %q exists", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if Token auth backend role %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if Token auth backend role %q exists", path)

	return resp != nil, nil
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
