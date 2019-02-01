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

func gcpAuthResourceCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := gcpRoleResourcePath(backend, role)

	data := map[string]interface{}{}

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

	if v, ok := d.GetOk("project_id"); ok {
		data["project_id"] = v.(string)
	}

	if v, ok := d.GetOk("bound_projects"); ok {
		data["bound_projects"] = v.(*schema.Set).List()
	}

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

	d.Set("ttl", resp.Data["ttl"])
	d.Set("max_ttl", resp.Data["max_ttl"])

	if v, ok := d.GetOk("project_id"); ok {
		d.Set("project_id", v)
	}
	if v, ok := d.GetOk("bound_projects"); ok {
		d.Set("bound_projects", v)
	}

	d.Set("period", resp.Data["period"])

	// These checks are done for backwards compatibility. The 'type' key used to be
	// 'role_type' and was changed to 'role' errorneously before being corrected
	if v, ok := resp.Data["type"]; ok {
		d.Set("type", v)
	} else if v, ok := resp.Data["role_type"]; ok {
		d.Set("type", v)
	} else if v, ok := resp.Data["role"]; ok {
		d.Set("type", v)
	}

	d.Set("policies",
		schema.NewSet(
			schema.HashString, resp.Data["policies"].([]interface{})))

	if accounts, ok := resp.Data["bound_service_accounts"]; ok {
		d.Set("bound_service_accounts",
			schema.NewSet(
				schema.HashString, accounts.([]interface{})))
	}

	if zones, ok := resp.Data["bound_zones"]; ok {
		d.Set("bound_zones", schema.NewSet(schema.HashString, zones.([]interface{})))
	}

	if regions, ok := resp.Data["bound_regions"]; ok {
		d.Set("bound_regions",
			schema.NewSet(
				schema.HashString, regions.([]interface{})))
	}

	if groups, ok := resp.Data["bound_instance_groups"]; ok {
		d.Set("bound_instance_groups",
			schema.NewSet(
				schema.HashString, groups.([]interface{})))
	}

	if labels, ok := resp.Data["bound_labels"]; ok {
		d.Set("bound_labels",
			schema.NewSet(
				schema.HashString, labels.([]interface{})))
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
