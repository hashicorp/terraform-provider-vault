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
	gcpAuthBackendFromPathRegex  = regexp.MustCompile("^auth/(.+)/role/[^/]+$")
	gcpAuthRoleNameFromPathRegex = regexp.MustCompile("^auth/.+/role/([^/]+)$")
)

func gcpAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role": {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		"type": {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		"bound_projects": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			ForceNew: true,
		},
		"project_id": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
			Removed:  `Use "bound_projects"`,
		},
		"add_group_aliases": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"max_jwt_exp": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"allow_gce_inference": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"bound_service_accounts": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"bound_zones": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"bound_regions": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"bound_instance_groups": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"bound_labels": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"backend": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
			Default:  "gcp",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},

		// Deprecated
		"ttl": {
			Type:          schema.TypeString,
			Optional:      true,
			Computed:      true,
			ConflictsWith: []string{"token_ttl"},
			Deprecated:    "use `token_ttl` instead if you are running Vault >= 1.2",
		},
		"max_ttl": {
			Type:          schema.TypeString,
			Optional:      true,
			Computed:      true,
			Deprecated:    "use `token_max_ttl` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_max_ttl"},
		},
		"period": {
			Type:          schema.TypeString,
			Optional:      true,
			Computed:      true,
			Deprecated:    "use `token_period` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_period"},
		},
		"policies": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			Computed:      true,
			Deprecated:    "use `token_policies` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_policies"},
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{
		TokenMaxTTLConflict:   []string{"max_ttl"},
		TokenPeriodConflict:   []string{"period"},
		TokenPoliciesConflict: []string{"policies"},
		TokenTTLConflict:      []string{"ttl"},
	})

	return &schema.Resource{
		SchemaVersion: 1,

		Create: gcpAuthResourceCreate,
		Update: gcpAuthResourceUpdate,
		Read:   gcpAuthResourceRead,
		Delete: gcpAuthResourceDelete,
		Exists: gcpAuthResourceExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func gcpRoleResourcePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func gcpRoleUpdateFields(d *schema.ResourceData, data map[string]interface{}, create bool) {
	updateTokenFields(d, data, create)

	if v, ok := d.GetOk("type"); ok {
		data["type"] = v.(string)
	}

	if v, ok := d.GetOk("project_id"); ok {
		data["project_id"] = v.(string)
	}

	if v, ok := d.GetOk("bound_projects"); ok {
		data["bound_projects"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(string)
	}

	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(string)
	}

	if v, ok := d.GetOk("period"); ok {
		data["period"] = v.(string)
	}

	if v, ok := d.GetOk("policies"); ok {
		data["policies"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("bound_service_accounts"); ok {
		data["bound_service_accounts"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOkExists("add_group_aliases"); ok {
		data["add_group_aliases"] = v.(bool)
	}

	if v, ok := d.GetOk("max_jwt_exp"); ok {
		data["max_jwt_exp"] = v.(string)
	}

	if v, ok := d.GetOkExists("allow_gce_inference"); ok {
		data["allow_gce_inference"] = v.(bool)
	}

	if v, ok := d.GetOk("bound_zones"); ok {
		data["bound_zones"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("bound_regions"); ok {
		data["bound_regions"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("bound_instance_groups"); ok {
		data["bound_instance_groups"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("bound_labels"); ok {
		data["bound_labels"] = v.(*schema.Set).List()
	}
}

func gcpAuthResourceCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := gcpRoleResourcePath(backend, role)

	data := map[string]interface{}{}
	gcpRoleUpdateFields(d, data, true)

	log.Printf("[DEBUG] Writing role %q to GCP auth backend", path)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error writing GCP auth role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote role %q to GCP auth backend", path)

	return gcpAuthResourceRead(d, meta)
}

func gcpAuthResourceUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	data := map[string]interface{}{}
	gcpRoleUpdateFields(d, data, false)

	log.Printf("[DEBUG] Updating role %q in GCP auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("Error updating GCP auth role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated role %q to GCP auth backend", path)

	return gcpAuthResourceRead(d, meta)
}

func gcpAuthResourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading GCP role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("Error reading GCP role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read GCP role %q", path)

	if resp == nil {
		log.Printf("[WARN] GCP role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	backend, err := gcpAuthResourceBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for GCP auth backend role: %s", path, err)
	}
	d.Set("backend", backend)
	role, err := gcpAuthResourceRoleFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for GCP auth backend role: %s", path, err)
	}
	d.Set("role", role)

	readTokenFields(d, resp)

	// Check if the user is using the deprecated `policies`
	if _, deprecated := d.GetOk("policies"); deprecated {
		// Then we see if `token_policies` was set and unset it
		// Vault will still return `policies`
		if _, ok := d.GetOk("token_policies"); ok {
			d.Set("token_policies", nil)
		}

		if v, ok := resp.Data["policies"]; ok {
			d.Set("policies", v)
		}
	}

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

	// Check if the user is using the deprecated `ttl`
	if _, deprecated := d.GetOk("ttl"); deprecated {
		// Then we see if `token_ttl` was set and unset it
		// Vault will still return `ttl`
		if _, ok := d.GetOk("token_ttl"); ok {
			d.Set("token_ttl", nil)
		}

		if v, ok := resp.Data["ttl"]; ok {
			d.Set("ttl", v)
		}

	}

	// Check if the user is using the deprecated `max_ttl`
	if _, deprecated := d.GetOk("max_ttl"); deprecated {
		// Then we see if `token_max_ttl` was set and unset it
		// Vault will still return `max_ttl`
		if _, ok := d.GetOk("token_max_ttl"); ok {
			d.Set("token_max_ttl", nil)
		}

		if v, ok := resp.Data["max_ttl"]; ok {
			d.Set("max_ttl", v)
		}
	}

	for _, k := range []string{"project_id", "bound_projects", "add_group_aliases", "max_jwt_exp", "bound_service_accounts", "bound_zones", "bound_regions", "bound_instance_groups"} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for GCP Auth Backend Role %q: %q", k, path, err)
			}
		}
	}

	if v, ok := resp.Data["bound_labels"]; ok {
		labels := []string{}
		for labelK, labelV := range v.(map[string]interface{}) {
			labels = append(labels, fmt.Sprintf("%s:%s", labelK, labelV))
		}

		if err := d.Set("bound_labels", labels); err != nil {
			return fmt.Errorf("error setting bound_labels for GCP auth backend role: %q", err)
		}
	}

	// These checks are done for backwards compatibility. The 'type' key used to be
	// 'role_type' and was changed to 'role' errorneously before being corrected
	if v, ok := resp.Data["type"]; ok {
		d.Set("type", v)
	} else if v, ok := resp.Data["role_type"]; ok {
		d.Set("type", v)
	} else if v, ok := resp.Data["role"]; ok {
		d.Set("type", v)
	}

	return nil
}

func gcpAuthResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting GCP role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting GCP role %q", path)
	}
	log.Printf("[DEBUG] Deleted GCP role %q", path)

	return nil
}

func gcpAuthResourceExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Checking if gcp auth role %q exists", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking for existence of gcp auth resource config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if gcp auth role %q exists", path)

	return resp != nil, nil
}

func gcpAuthResourceBackendFromPath(path string) (string, error) {
	if !gcpAuthBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := gcpAuthBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func gcpAuthResourceRoleFromPath(path string) (string, error) {
	if !gcpAuthRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := gcpAuthRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}
