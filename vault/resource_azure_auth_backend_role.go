package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	azureAuthBackendRoleBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/role/.+$")
	azureAuthBackendRoleNameFromPathRegex    = regexp.MustCompile("^auth/.+/role/(.+)$")
)

func azureAuthBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: azureAuthBackendRoleCreate,
		Read:   azureAuthBackendRoleRead,
		Update: azureAuthBackendRoleUpdate,
		Delete: azureAuthBackendRoleDelete,
		Exists: azureAuthBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role.",
				ForceNew:    true,
			},
			"bound_service_principal_ids": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "The list of Service Principal IDs that login is restricted to.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"bound_group_ids": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "The list of group ids that login is restricted to.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"bound_locations": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "The list of locations that login is restricted to.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"bound_subscription_ids": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "The list of subscription IDs that login is restricted to.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"bound_resource_groups": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "The list of resource groups that login is restricted to.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"bound_scale_sets": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "The list of scale set names that the login is restricted to.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The TTL period of tokens issued using this role, provided as the number of seconds.",
			},
			"max_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The maximum allowed lifetime of tokens issued using this role, provided as the number of seconds.",
			},
			"period": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "If set, indicates that the token generated using this role should never expire. The token should be renewed within the duration specified by this value. At each renewal, the token's TTL will be set to the value of this field. The maximum allowed lifetime of token issued using this role. Specified as a number of seconds.",
			},
			"policies": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Policies to be set on tokens issued using this role.",
			},
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "azure",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func azureAuthBackendRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := azureAuthBackendRolePath(backend, role)

	log.Printf("[DEBUG] Writing Azure auth backend role %q", path)
	iPolicies := d.Get("policies").([]interface{})
	policies := make([]string, len(iPolicies))
	for i, iPolicy := range iPolicies {
		policies[i] = iPolicy.(string)
	}

	data := map[string]interface{}{}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(int)
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(int)
	}
	if v, ok := d.GetOk("period"); ok {
		data["period"] = v.(int)
	}
	if len(policies) > 0 {
		data["policies"] = policies
	}

	if _, ok := d.GetOk("bound_service_principal_ids"); ok {
		iSPI := d.Get("bound_service_principal_ids").([]interface{})
		bound_service_principal_ids := make([]string, len(iSPI))
		for i, iSP := range iSPI {
			bound_service_principal_ids[i] = iSP.(string)
		}
		data["bound_service_principal_ids"] = bound_service_principal_ids
	}

	if _, ok := d.GetOk("bound_group_ids"); ok {
		iGI := d.Get("bound_group_ids").([]interface{})
		bound_group_ids := make([]string, len(iGI))
		for i, iG := range iGI {
			bound_group_ids[i] = iG.(string)
		}
		data["bound_group_ids"] = bound_group_ids
	}

	if _, ok := d.GetOk("bound_locations"); ok {
		iLS := d.Get("bound_locations").([]interface{})
		bound_locations := make([]string, len(iLS))
		for i, iL := range iLS {
			bound_locations[i] = iL.(string)
		}
		data["bound_locations"] = bound_locations
	}

	if _, ok := d.GetOk("bound_subscription_ids"); ok {
		iSI := d.Get("bound_subscription_ids").([]interface{})
		bound_subscription_ids := make([]string, len(iSI))
		for i, iS := range iSI {
			bound_subscription_ids[i] = iS.(string)
		}
		data["bound_subscription_ids"] = bound_subscription_ids
	}

	if _, ok := d.GetOk("bound_resource_groups"); ok {
		iRGN := d.Get("bound_resource_groups").([]interface{})
		bound_resource_groups := make([]string, len(iRGN))
		for i, iRG := range iRGN {
			bound_resource_groups[i] = iRG.(string)
		}
		data["bound_resource_groups"] = bound_resource_groups
	}

	if _, ok := d.GetOk("bound_scale_sets"); ok {
		iSS := d.Get("bound_scale_sets").([]interface{})
		bound_scale_sets := make([]string, len(iSS))
		for i, iS := range iSS {
			bound_scale_sets[i] = iS.(string)
		}
		data["bound_scale_sets"] = bound_scale_sets
	}

	d.SetId(path)
	if _, err := client.Logical().Write(path, data); err != nil {
		d.SetId("")
		return fmt.Errorf("error writing Azure auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Azure auth backend role %q", path)

	return azureAuthBackendRoleRead(d, meta)
}

func azureAuthBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	backend, err := azureAuthBackendRoleBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for Azure auth backend role: %s", path, err)
	}

	role, err := azureAuthBackendRoleNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for Azure auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading Azure auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading Azure auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Azure auth backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] Azure auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	iPolicies := resp.Data["policies"].([]interface{})
	policies := make([]string, len(iPolicies))
	for i, iPolicy := range iPolicies {
		policies[i] = iPolicy.(string)
	}

	ttl, err := resp.Data["ttl"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected ttl %q to be a number, isn't", resp.Data["ttl"])
	}

	maxTTL, err := resp.Data["max_ttl"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected max_ttl %q to be a number, isn't", resp.Data["max_ttl"])
	}

	period, err := resp.Data["period"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected period %q to be a number, isn't", resp.Data["period"])
	}

	d.Set("backend", backend)
	d.Set("role", role)

	if _, ok := d.GetOk("bound_service_principal_ids"); ok {
		d.Set("bound_service_principal_ids", resp.Data["bound_service_principal_ids"])
	}

	if _, ok := d.GetOk("bound_group_ids"); ok {
		d.Set("bound_group_ids", resp.Data["bound_group_ids"])
	}

	if _, ok := d.GetOk("bound_locations"); ok {
		d.Set("bound_locations", resp.Data["bound_locations"])
	}

	if _, ok := d.GetOk("bound_subscription_ids"); ok {
		d.Set("bound_subscription_ids", resp.Data["bound_subscription_ids"])
	}

	if _, ok := d.GetOk("bound_resource_groups"); ok {
		d.Set("bound_resource_groups", resp.Data["bound_resource_groups"])
	}

	if _, ok := d.GetOk("bound_scale_sets"); ok {
		d.Set("bound_scale_sets", resp.Data["bound_scale_sets"])
	}

	d.Set("ttl", ttl)
	d.Set("max_ttl", maxTTL)
	d.Set("period", period)
	d.Set("policies", policies)

	return nil
}

func azureAuthBackendRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Updating Azure auth backend role %q", path)
	iPolicies := d.Get("policies").([]interface{})
	policies := make([]string, len(iPolicies))
	for i, iPolicy := range iPolicies {
		policies[i] = iPolicy.(string)
	}

	data := map[string]interface{}{}
	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(int)
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(int)
	}
	if v, ok := d.GetOk("period"); ok {
		data["period"] = v.(int)
	}
	if len(policies) > 0 {
		data["policies"] = policies
	}
	if _, ok := d.GetOk("bound_service_principal_ids"); ok {
		iSPI := d.Get("bound_service_principal_ids").([]interface{})
		bound_service_principal_ids := make([]string, len(iSPI))
		for i, iSP := range iSPI {
			bound_service_principal_ids[i] = iSP.(string)
		}
		data["bound_service_principal_ids"] = bound_service_principal_ids
	}
	if _, ok := d.GetOk("bound_group_ids"); ok {
		iGI := d.Get("bound_group_ids").([]interface{})
		bound_group_ids := make([]string, len(iGI))
		for i, iG := range iGI {
			bound_group_ids[i] = iG.(string)
		}
		data["bound_group_ids"] = bound_group_ids
	}
	if _, ok := d.GetOk("bound_locations"); ok {
		iLS := d.Get("bound_locations").([]interface{})
		bound_locations := make([]string, len(iLS))
		for i, iL := range iLS {
			bound_locations[i] = iL.(string)
		}
		data["bound_locations"] = bound_locations
	}
	if _, ok := d.GetOk("bound_subscription_ids"); ok {
		iSI := d.Get("bound_subscription_ids").([]interface{})
		bound_subscription_ids := make([]string, len(iSI))
		for i, iS := range iSI {
			bound_subscription_ids[i] = iS.(string)
		}
		data["bound_subscription_ids"] = bound_subscription_ids
	}
	if _, ok := d.GetOk("bound_resource_groups"); ok {
		iRGN := d.Get("bound_resource_groups").([]interface{})
		bound_resource_groups := make([]string, len(iRGN))
		for i, iRG := range iRGN {
			bound_resource_groups[i] = iRG.(string)
		}
		data["bound_resource_groups"] = bound_resource_groups
	}
	if _, ok := d.GetOk("bound_scale_sets"); ok {
		iSS := d.Get("bound_scale_sets").([]interface{})
		bound_scale_sets := make([]string, len(iSS))
		for i, iS := range iSS {
			bound_scale_sets[i] = iS.(string)
		}
		data["bound_scale_sets"] = bound_scale_sets
	}
	log.Printf("[DEBUG] Updating role %q in Azure auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("Error updating Azure auth role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated role %q to Azure auth backend", path)

	return azureAuthBackendRoleRead(d, meta)
}

func azureAuthBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting Azure auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting Azure auth backend role %q", path)
	}
	log.Printf("[DEBUG] Deleted Azure auth backend role %q", path)

	return nil
}

func azureAuthBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if Azure auth backend role %q exists", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if Azure auth backend role %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if Azure auth backend role %q exists", path)

	return resp != nil, nil
}

func azureAuthBackendRolePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func azureAuthBackendRoleNameFromPath(path string) (string, error) {
	if !azureAuthBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := azureAuthBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func azureAuthBackendRoleBackendFromPath(path string) (string, error) {
	if !azureAuthBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := azureAuthBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
