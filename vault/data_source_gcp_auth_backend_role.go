package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	gcpRoleFields = []string{
		"role_id",
		"type",
		"bound_service_accounts",
		"bound_projects",
		"bound_zones",
		"bound_regions",
		"bound_instance_groups",
		"bound_labels",
		"token_policies",
	}
)

func gcpAuthBackendRoleDataSource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role_name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role.",
			ForceNew:    true,
		},
		"role_id": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "The RoleID of the GCP auth role.",
		},
		"backend": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Unique name of the auth backend to configure.",
			ForceNew:    true,
			Default:     "gcp",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"type": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"bound_service_accounts": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Computed: true,
		},
		"bound_projects": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Computed: true,
		},
		"bound_zones": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Computed: true,
		},
		"bound_regions": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Computed: true,
		},
		"bound_instance_groups": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Computed: true,
		},
		"bound_labels": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Computed: true,
		},
		"token_policies": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Computed: true,
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		Read:   gcpAuthBackendRoleRead,
		Schema: fields,
	}
}

func gcpAuthBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := gcpRoleResourcePath(d.Get("backend").(string), d.Get("role_name").(string))

	log.Printf("[DEBUG] Reading gcp auth backend role %q ID", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading gcp auth backend role %q ID: %s", path, err)
	}
	log.Printf("[DEBUG] Read gcp auth backend role %q ID", path)

	if resp == nil {
		d.SetId("")
		return nil
	}
	d.SetId(path)
	for _, k := range gcpRoleFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for GCP Auth Backend Role %q: %q", k, path, err)
			}
		}
	}

	readTokenFields(d, resp)

	return nil
}
