package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"

	"github.com/hashicorp/vault/api"
)

func gcpAuthBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: gcpAuthResourceCreate,
		Update: gcpAuthResourceUpdate,
		Read:   gcpAuthResourceRead,
		Delete: gcpAuthResourceDelete,

		Schema: map[string]*schema.Schema{
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
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"project_id"},
			},
			"project_id": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				Deprecated:    `Use "bound_projects"`,
				ConflictsWith: []string{"bound_projects"},
			},
			"ttl": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"max_ttl": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"period": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"policies": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
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
		},
	}
}

func gcpRoleResourcePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func gcpRoleUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
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

	if v, ok := d.GetOk("bound_instance_labels"); ok {
		data["bound_instance_labels"] = v.(*schema.Set).List()
	}
}

func gcpAuthResourceCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := gcpRoleResourcePath(backend, role)

	data := map[string]interface{}{}
	gcpRoleUpdateFields(d, data)

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
	gcpRoleUpdateFields(d, data)

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

	for _, k := range []string{"ttl", "max_ttl", "project_id", "bound_projects", "period", "policies", "add_group_aliases", "max_jwt_exp", "bound_service_accounts", "bound_zones", "bound_regions", "bound_instance_groups", "bound_labels"} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for GCP Auth Backend Role %q: %q", k, path, err)
			}
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
