package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	tokenAuthBackendRoleNameFromPathRegex = regexp.MustCompile("^auth/token/roles/(.+)$")
)

func tokenAuthBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: tokenAuthBackendRoleCreate,
		Read:   tokenAuthBackendRoleRead,
		Update: tokenAuthBackendRoleUpdate,
		Delete: tokenAuthBackendRoleDelete,
		Exists: tokenAuthBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role.",
			},
			"allowed_policies": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of allowed policies for given role.",
			},
			"disallowed_policies": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of disallowed policies for given role.",
			},
			"orphan": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If true, tokens created against this policy will be orphan tokens.",
			},
			"period": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The duration in which a token should be renewed. At each renewal, the token's TTL will be set to the value of this parameter.",
			},
			"renewable": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Wether to disable the ability of the token to be renewed past its initial TTL.",
			},
			"explicit_max_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "If set, the token will have an explicit max TTL set upon it.",
			},
			"path_suffix": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Tokens created against this role will have the given suffix as part of their path in addition to the role name.",
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The TTL period of tokens issued using this role, provided as the number of minutes.",
			},
			"max_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The maximum allowed lifetime of tokens issued using this role.",
			},
		},
	}
}

func tokenAuthBackendRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	role := d.Get("role_name").(string)

	path := tokenAuthBackendRolePath(role)

	log.Printf("[DEBUG] Writing Token auth backend role %q", path)

	iAllowedPolicies := d.Get("allowed_policies").([]interface{})
	allowedPolicies := make([]string, 0, len(iAllowedPolicies))
	for _, iPolicy := range iAllowedPolicies {
		allowedPolicies = append(allowedPolicies, iPolicy.(string))
	}

	iDisallowedPolicies := d.Get("disallowed_policies").([]interface{})
	disallowedPolicies := make([]string, 0, len(iDisallowedPolicies))
	for _, iPolicy := range iDisallowedPolicies {
		disallowedPolicies = append(disallowedPolicies, iPolicy.(string))
	}

	data := map[string]interface{}{}

	if len(allowedPolicies) > 0 {
		data["allowed_policies"] = allowedPolicies
	}

	if len(disallowedPolicies) > 0 {
		data["disallowed_policies"] = disallowedPolicies
	}

	data["explicit_max_ttl"] = d.Get("explicit_max_ttl").(string)
	data["ttl"] = d.Get("ttl").(string)
	data["max_ttl"] = d.Get("max_ttl").(string)
	data["orphan"] = d.Get("orphan").(bool)
	data["renewable"] = d.Get("renewable").(bool)
	data["path_suffix"] = d.Get("path_suffix").(string)

	_, err := client.Logical().Write(path, data)

	d.SetId(path)

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

	iAllowedPolicies := resp.Data["allowed_policies"].([]interface{})
	allowedPolicies := make([]string, 0, len(iAllowedPolicies))
	for _, iAllowedPolicy := range iAllowedPolicies {
		allowedPolicies = append(allowedPolicies, iAllowedPolicy.(string))
	}

	iDisallowedPolicies := resp.Data["disallowed_policies"].([]interface{})
	disallowedPolicies := make([]string, 0, len(iDisallowedPolicies))
	for _, iDisallowedPolicy := range iDisallowedPolicies {
		disallowedPolicies = append(disallowedPolicies, iDisallowedPolicy.(string))
	}

	d.Set("role_name", roleName)
	d.Set("allowed_policies", allowedPolicies)
	d.Set("disallowed_policies", disallowedPolicies)
	d.Set("orphan", resp.Data["orphan"])
	d.Set("period", resp.Data["period"])
	d.Set("renewable", resp.Data["renewable"])
	d.Set("explicit_max_ttl", resp.Data["explicit_max_ttl"])
	d.Set("path_suffix", resp.Data["path_suffix"])
	d.Set("ttl", resp.Data["ttl"])
	d.Set("max_ttl", resp.Data["max_ttl"])

	return nil
}

func tokenAuthBackendRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Updating Token auth backend role %q", path)

	iAllowedPolicies := d.Get("allowed_policies").([]interface{})
	allowedPolicies := make([]string, 0, len(iAllowedPolicies))
	for _, iPolicy := range iAllowedPolicies {
		allowedPolicies = append(allowedPolicies, iPolicy.(string))
	}

	iDisallowedPolicies := d.Get("disallowed_policies").([]interface{})
	disallowedPolicies := make([]string, 0, len(iDisallowedPolicies))
	for _, iPolicy := range iDisallowedPolicies {
		disallowedPolicies = append(disallowedPolicies, iPolicy.(string))
	}

	data := map[string]interface{}{}

	if len(allowedPolicies) > 0 {
		data["allowed_policies"] = allowedPolicies
	}
	if len(disallowedPolicies) > 0 {
		data["disallowed_policies"] = disallowedPolicies
	}

	data["orphan"] = d.Get("orphan").(bool)
	data["period"] = d.Get("period").(string)
	data["renewable"] = d.Get("renewable").(bool)
	data["explicit_max_ttl"] = d.Get("explicit_max_ttl").(string)
	data["path_suffix"] = d.Get("path_suffix").(string)
	data["ttl"] = d.Get("ttl").(string)
	data["max_ttl"] = d.Get("max_ttl").(string)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("Error updating Token auth backend role %q: %s", path, err)
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
		return fmt.Errorf("Error deleting Token auth backend role %q", path)
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
		return true, fmt.Errorf("Error checking if Token auth backend role %q exists: %s", path, err)
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
