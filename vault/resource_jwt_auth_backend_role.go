package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

var (
	jwtAuthBackendRoleBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/role/.+$")
	jwtAuthBackendRoleNameFromPathRegex    = regexp.MustCompile("^auth/.+/role/(.+)$")
)

func jwtAuthBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: jwtAuthBackendRoleCreate,
		Read:   jwtAuthBackendRoleRead,
		Update: jwtAuthBackendRoleUpdate,
		Delete: jwtAuthBackendRoleDelete,
		Exists: jwtAuthBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role.",
				ForceNew:    true,
			},
			"bound_audiences": {
				Type:        schema.TypeSet,
				Required:    true,
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
			"policies": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Policies to be set on tokens issued using this role.",
			},
			"ttl": {
				Type:          schema.TypeInt,
				Optional:      true,
				Description:   "Default number of seconds to set as the TTL for issued tokens and at renewal time.",
				ConflictsWith: []string{"period"},
			},
			"max_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of seconds after which issued tokens can no longer be renewed.",
			},
			"period": {
				Type:          schema.TypeInt,
				Optional:      true,
				Description:   "Number of seconds to set the TTL to for issued tokens upon renewal. Makes the token a periodic token, which will never expire as long as it is renewed before the TTL each period.",
				ConflictsWith: []string{"ttl"},
			},
			"num_uses": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of times issued tokens can be used. Setting this to 0 or leaving it unset means unlimited uses.",
			},
			"bound_subject": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "If set, requires that the sub claim matches this value.",
			},
			"bound_cidrs": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of CIDRs valid as the source address for login requests. This value is also encoded into any resulting token.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"groups_claim": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The claim to use to uniquely identify the set of groups to which the user belongs; this will be used as the names for the Identity group aliases created due to a successful login. The claim value must be a list of strings.",
			},
			"groups_claim_delimiter_pattern": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A pattern of delimiters used to allow the groups_claim to live outside of the top-level JWT structure. For instance, a groups_claim of meta/user.name/groups with this field set to // will expect nested structures named meta, user.name, and groups. If this field was set to /./ the groups information would expect to be via nested structures of meta, user, name, and groups.",
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
		},
	}
}

func jwtAuthBackendRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role_name").(string)
	path := jwtAuthBackendRolePath(backend, role)

	log.Printf("[DEBUG] Writing JWT auth backend role %q", path)
	data := jwtAuthBackendRoleDataToWrite(d)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing JWT auth backend role %q: %s", path, err)
	}
	d.SetId(path)
	log.Printf("[DEBUG] Wrote JWT auth backend role %q", path)

	if v, ok := d.GetOk("role_id"); ok {
		log.Printf("[DEBUG] Writing JWT auth backend role %q RoleID", path)
		_, err := client.Logical().Write(path+"/role-id", map[string]interface{}{
			"role_id": v.(string),
		})
		if err != nil {
			return fmt.Errorf("error writing JWT auth backend role %q's RoleID: %s", path, err)
		}
		log.Printf("[DEBUG] Wrote JWT auth backend role %q RoleID", path)
	}

	return jwtAuthBackendRoleRead(d, meta)
}

func jwtAuthBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	backend, err := jwtAuthBackendRoleBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for JWT auth backend role: %s", path, err)
	}

	role, err := jwtAuthBackendRoleNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for JWT auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading JWT auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading JWT auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read JWT auth backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] JWT auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	boundAuds := util.JsonStringArrayToStringArray(resp.Data["bound_audiences"].([]interface{}))
	err = d.Set("bound_audiences", boundAuds)
	if err != nil {
		return fmt.Errorf("error setting bound_audiences in state: %s", err)
	}

	d.Set("user_claim", resp.Data["user_claim"].(string))

	policies := util.JsonStringArrayToStringArray(resp.Data["policies"].([]interface{}))
	err = d.Set("policies", policies)
	if err != nil {
		return fmt.Errorf("error setting policies in state: %s", err)
	}

	tokenTTL, err := resp.Data["ttl"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected ttl %q to be a number, isn't", resp.Data["ttl"])
	}
	d.Set("ttl", tokenTTL)

	tokenMaxTTL, err := resp.Data["max_ttl"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected max_ttl %q to be a number, isn't", resp.Data["max_ttl"])
	}
	d.Set("max_ttl", tokenMaxTTL)

	period, err := resp.Data["period"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected period %q to be a number, isn't", resp.Data["period"])
	}
	d.Set("period", period)

	tokenNumUses, err := resp.Data["num_uses"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected token_num_uses %q to be a number, isn't", resp.Data["num_uses"])
	}
	d.Set("num_uses", tokenNumUses)

	d.Set("bound_subject", resp.Data["bound_subject"].(string))

	if resp.Data["bound_cidrs"] != nil {
		cidrs := util.JsonStringArrayToStringArray(resp.Data["bound_cidrs"].([]interface{}))
		err = d.Set("bound_cidrs", cidrs)
		if err != nil {
			return fmt.Errorf("error setting bound_cidrs in state: %s", err)
		}
	} else {
		d.Set("bound_cidrs", make([]string, 0))
	}

	d.Set("groups_claim", resp.Data["groups_claim"].(string))
	d.Set("groups_claim_delimiter_pattern", resp.Data["groups_claim_delimiter_pattern"].(string))

	d.Set("backend", backend)
	d.Set("role_name", role)

	return nil
}

func jwtAuthBackendRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Updating JWT auth backend role %q", path)
	data := jwtAuthBackendRoleDataToWrite(d)
	_, err := client.Logical().Write(path, data)

	d.SetId(path)

	if err != nil {
		return fmt.Errorf("error updating JWT auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated JWT auth backend role %q", path)

	if d.HasChange("role_id") {
		log.Printf("[DEBUG] Updating JWT auth backend role %q RoleID", path)
		_, err := client.Logical().Write(path+"/role-id", map[string]interface{}{
			"role_id": d.Get("role_id").(string),
		})
		if err != nil {
			return fmt.Errorf("error updating JWT auth backend role %q's RoleID: %s", path, err)
		}
		log.Printf("[DEBUG] Updated JWT auth backend role %q RoleID", path)
	}

	return jwtAuthBackendRoleRead(d, meta)

}

func jwtAuthBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting JWT auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil && !util.Is404(err) {
		return fmt.Errorf("error deleting JWT auth backend role %q", path)
	} else if err != nil {
		log.Printf("[DEBUG] JWT auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted JWT auth backend role %q", path)

	return nil
}

func jwtAuthBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if JWT auth backend role %q exists", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if JWT auth backend role %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if JWT auth backend role %q exists", path)

	return resp != nil, nil
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

func jwtAuthBackendRoleDataToWrite(d *schema.ResourceData) map[string]interface{} {
	data := map[string]interface{}{}

	data["bound_audiences"] = util.TerraformSetToStringArray(d.Get("bound_audiences"))
	data["user_claim"] = d.Get("user_claim").(string)

	if dataList := util.TerraformSetToStringArray(d.Get("policies")); len(dataList) > 0 {
		data["policies"] = dataList
	}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(int)
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(int)
	}
	if v, ok := d.GetOk("period"); ok {
		data["period"] = v.(int)
	}
	if v, ok := d.GetOk("num_uses"); ok {
		data["num_uses"] = v.(int)
	}

	if v, ok := d.GetOkExists("bound_subject"); ok {
		data["bound_subject"] = v.(string)
	}

	if dataList := util.TerraformSetToStringArray(d.Get("bound_cidrs")); len(dataList) > 0 {
		data["bound_cidrs"] = dataList
	}

	if v, ok := d.GetOkExists("groups_claim"); ok {
		data["groups_claim"] = v.(string)
	}

	if v, ok := d.GetOkExists("groups_claim_delimiter_pattern"); ok {
		data["groups_claim_delimiter_pattern"] = v.(string)
	}

	return data
}
