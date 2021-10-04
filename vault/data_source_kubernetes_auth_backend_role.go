package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func kubernetesAuthBackendRoleDataSource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"backend": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Unique name of the kubernetes backend to configure.",
			ForceNew:    true,
			Default:     "kubernetes",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"role_name": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Name of the role.",
		},
		"bound_service_account_names": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Description: "List of service account names able to access this role. If set to \"*\" all names are allowed, both this and bound_service_account_namespaces can not be \"*\".",
			Computed:    true,
		},
		"bound_service_account_namespaces": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Description: "List of namespaces allowed to access this role. If set to \"*\" all namespaces are allowed, both this and bound_service_account_names can not be set to \"*\".",
			Computed:    true,
		},
		"audience": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "Optional Audience claim to verify in the JWT.",
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		Read:   kubernetesAuthBackendRoleDataSourceRead,
		Schema: fields,
	}
}

func kubernetesAuthBackendRoleDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role_name").(string)
	path := kubernetesAuthBackendRolePath(backend, role)

	log.Printf("[DEBUG] Reading Kubernetes auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading Kubernetes auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Kubernetes auth backend role %q", path)

	if resp == nil {
		d.SetId("")
		return nil
	}
	d.SetId(path)

	if err := readTokenFields(d, resp); err != nil {
		return err
	}

	for _, k := range []string{"bound_service_account_names", "bound_service_account_namespaces", "audience"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return err
		}
	}
	return nil
}
