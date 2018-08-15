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
	tokenRoleNameFromPathRegex = regexp.MustCompile("^auth/token/roles/(.+)$")
)

func tokenRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: tokenRoleCreate,
		Read:   tokenRoleRead,
		Update: tokenRoleUpdate,
		Delete: tokenRoleDelete,
		Exists: tokenRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the role.",
			},
			"allowed_policies": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The allowed policies of the role.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"disallowed_policies": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The disallowed policies of the role.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"orphan": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     false,
				Description: "Flag to create orphan tokens.",
			},
			"period": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     "0",
				Description: "The period of tokens.",
			},
			"renewable": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     true,
				Description: "Flag to allow tokens to be renewed",
			},
			"explicit_max_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     "0",
				Description: "The explicit max TTL of tokens.",
			},
			"path_suffix": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The path suffix of tokens in addition to the role name.",
			},
			"bound_cidrs": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "List of restricted client IPs to use tokens.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func tokenRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	path := tokenRolePath(name)

	log.Printf("[DEBUG] Writing token role %q", path)

	iAllowedPolicies := d.Get("allowed_policies").([]interface{})
	allowedPolicies := make([]string, 0, len(iAllowedPolicies))
	for _, iAllowedPolicy := range iAllowedPolicies {
		allowedPolicies = append(allowedPolicies, iAllowedPolicy.(string))
	}

	iDisallowedPolicies := d.Get("disallowed_policies").([]interface{})
	disallowedPolicies := make([]string, 0, len(iDisallowedPolicies))
	for _, iDisallowedPolicy := range iDisallowedPolicies {
		disallowedPolicies = append(disallowedPolicies, iDisallowedPolicy.(string))
	}

	iBoundCIDRs := d.Get("bound_cidrs").([]interface{})
	boundCIDRs := make([]string, 0, len(iBoundCIDRs))
	for _, iBoundCIDR := range iBoundCIDRs {
		boundCIDRs = append(boundCIDRs, iBoundCIDR.(string))
	}

	data := map[string]interface{}{
		"name":             d.Get("name").(string),
		"orphan":           d.Get("orphan").(bool),
		"period":           d.Get("period").(string),
		"renewable":        d.Get("renewable").(bool),
		"explicit_max_ttl": d.Get("explicit_max_ttl").(string),
		"path_suffix":      d.Get("path_suffix").(string),
	}

	if len(allowedPolicies) > 0 {
		data["allowed_policies"] = allowedPolicies
	}

	if len(disallowedPolicies) > 0 {
		data["disallowed_policies"] = disallowedPolicies
	}

	if len(boundCIDRs) > 0 {
		data["bound_cidrs"] = boundCIDRs
	}

	log.Printf("[DEBUG] Creating token role %s", name)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating token role %s: %s", name, err)
	}
	log.Printf("[DEBUG] Created token role %s", name)

	d.SetId(path)

	return tokenRoleRead(d, meta)
}

func tokenRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	name, err := tokenRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading role %s", name)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading role %s: %s", name, err)
	}
	log.Printf("[DEBUG] Read role %s", name)
	if resp == nil {
		log.Printf("[WARN] Role %s not found, removing from state", name)
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

	d.Set("name", name)
	d.Set("allowed_policies", allowedPolicies)
	d.Set("disallowed_policies", disallowedPolicies)
	d.Set("orphan", resp.Data["orphan"])
	d.Set("period", resp.Data["period"])
	d.Set("renewable", resp.Data["renewable"])
	d.Set("explicit_max_ttl", resp.Data["explicit_max_ttl"])
	d.Set("path_suffix", resp.Data["path_suffix"])

	return nil
}

func tokenRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	name, err := tokenRoleNameFromPath(path)
	log.Printf("[DEBUG] Updating token role %s", name)

	iAllowedPolicies := d.Get("allowed_policies").([]interface{})
	allowedPolicies := make([]string, 0, len(iAllowedPolicies))
	for _, iAllowedPolicy := range iAllowedPolicies {
		allowedPolicies = append(allowedPolicies, iAllowedPolicy.(string))
	}

	iDisallowedPolicies := d.Get("disallowed_policies").([]interface{})
	disallowedPolicies := make([]string, 0, len(iDisallowedPolicies))
	for _, iDisallowedPolicy := range iDisallowedPolicies {
		disallowedPolicies = append(disallowedPolicies, iDisallowedPolicy.(string))
	}

	iBoundCIDRs := d.Get("bound_cidrs").([]interface{})
	boundCIDRs := make([]string, 0, len(iBoundCIDRs))
	for _, iBoundCIDR := range iBoundCIDRs {
		boundCIDRs = append(boundCIDRs, iBoundCIDR.(string))
	}

	data := map[string]interface{}{
		"orphan":           d.Get("orphan").(bool),
		"period":           d.Get("period").(string),
		"renewable":        d.Get("renewable").(bool),
		"explicit_max_ttl": d.Get("explicit_max_ttl").(string),
		"path_suffix":      d.Get("path_suffix").(string),
	}

	if len(allowedPolicies) > 0 {
		data["allowed_policies"] = allowedPolicies
	}

	if len(disallowedPolicies) > 0 {
		data["disallowed_policies"] = disallowedPolicies
	}

	if len(boundCIDRs) > 0 {
		data["bound_cidrs"] = boundCIDRs
	}

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating token role %s: %s", name, err)
	}
	log.Printf("[DEBUG] Updated token role %s", name)

	return tokenRoleRead(d, meta)
}

func tokenRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Deleting role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted role %q", path)

	return nil
}

func tokenRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Checking if role %q exists", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if role %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if role %q exists", path)

	return resp != nil, nil
}

func tokenRolePath(name string) string {
	return "auth/token/roles/" + strings.Trim(name, "/")
}

func tokenRoleNameFromPath(path string) (string, error) {
	if !tokenRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}

	res := tokenRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}

	return res[1], nil
}
