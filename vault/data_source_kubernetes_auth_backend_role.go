package vault

import (
	"strings"

	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
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
		// Deprecated
		"policies": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Description: "Policies to be set on tokens issued using this role.",
			Deprecated:  "use `token_policies` instead if you are running Vault >= 1.2",
		},
		"ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "Default number of seconds to set as the TTL for issued tokens and at renewal time.",
			Deprecated:  "use `token_ttl` instead if you are running Vault >= 1.2",
		},
		"max_ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "Number of seconds after which issued tokens can no longer be renewed.",
			Deprecated:  "use `token_max_ttl` instead if you are running Vault >= 1.2",
		},
		"period": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "Number of seconds to set the TTL to for issued tokens upon renewal. Makes the token a periodic token, which will never expire as long as it is renewed before the TTL each period.",
			Deprecated:  "use `token_period` instead if you are running Vault >= 1.2",
		},
		"num_uses": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "Number of times issued tokens can be used. Setting this to 0 or leaving it unset means unlimited uses.",
			Deprecated:  "use `token_num_uses` instead if you are running Vault >= 1.2",
		},
		"bound_cidrs": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of CIDRs valid as the source address for login requests. This value is also encoded into any resulting token.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Deprecated: "use `token_bound_cidrs` instead if you are running Vault >= 1.2",
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

	readTokenFields(d, resp)

	for _, k := range []string{"bound_cidrs", "bound_service_account_names", "bound_service_account_namespaces", "num_uses", "policies", "ttl", "max_ttl", "period"} {
		d.Set(k, resp.Data[k])
	}
	return nil
}
