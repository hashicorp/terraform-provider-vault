package vault

import (
	"strings"

	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"log"
)

func kubernetesAuthBackendRoleDataSource() *schema.Resource {
	return &schema.Resource{
		Read: kubernetesAuthBackendRoleDataSourceRead,
		Schema: map[string]*schema.Schema{
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
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of service account names able to access this role. If set to \"*\" all names are allowed, both this and bound_service_account_namespaces can not be \"*\".",
				Computed:    true,
			},
			"bound_service_account_namespaces": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of namespaces allowed to access this role. If set to \"*\" all namespaces are allowed, both this and bound_service_account_names can not be set to \"*\".",
				Computed:    true,
			},
			"ttl": {
				Type:        schema.TypeInt,
				Description: "The TTL period of tokens issued using this role in seconds.",
				Computed:    true,
				Optional:    true,
			},
			"max_ttl": {
				Type:        schema.TypeInt,
				Description: "The maximum allowed lifetime of tokens issued in seconds using this role.",
				Computed:    true,
				Optional:    true,
			},
			"num_uses": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Number of times issued tokens can be used. Setting this to 0 or leaving it unset means unlimited uses.",
			},
			"period": {
				Type:        schema.TypeInt,
				Description: "If set, indicates that the token generated using this role should never expire. The token should be renewed within the duration specified by this value. At each renewal, the token's TTL will be set to the value of this parameter.",
				Computed:    true,
				Optional:    true,
			},
			"policies": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Policies to be set on tokens issued using this role.",
				Computed:    true,
				Optional:    true,
			},
		},
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

	iBoundServiceAccountNames := resp.Data["bound_service_account_names"].([]interface{})
	boundServiceAccountNames := make([]string, 0, len(iBoundServiceAccountNames))

	for _, iBoundServiceAccountName := range iBoundServiceAccountNames {
		boundServiceAccountNames = append(boundServiceAccountNames, iBoundServiceAccountName.(string))
	}

	d.Set("bound_service_account_names", boundServiceAccountNames)

	iBoundServiceAccountNamespaces := resp.Data["bound_service_account_namespaces"].([]interface{})
	boundServiceAccountNamespaces := make([]string, 0, len(iBoundServiceAccountNamespaces))

	for _, iBoundServiceAccountNamespace := range iBoundServiceAccountNamespaces {
		boundServiceAccountNamespaces = append(boundServiceAccountNamespaces, iBoundServiceAccountNamespace.(string))
	}

	d.Set("bound_service_account_namespaces", boundServiceAccountNamespaces)

	iPolicies := resp.Data["policies"].([]interface{})
	policies := make([]string, 0, len(iPolicies))

	for _, iPolicy := range iPolicies {
		policies = append(policies, iPolicy.(string))
	}

	d.Set("policies", policies)

	ttl, err := resp.Data["ttl"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected `ttl` %q to be a number, isn't", resp.Data["ttl"])
	}
	d.Set("ttl", ttl)

	maxTTL, err := resp.Data["max_ttl"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected `max_ttl` %q to be a number, isn't", resp.Data["max_ttl"])
	}
	d.Set("max_ttl", maxTTL)

	numUses, err := resp.Data["num_uses"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected `num_uses` %q to be a number, isn't", resp.Data["num_uses"])
	}
	d.Set("num_uses", numUses)

	period, err := resp.Data["period"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected `period` %q to be a number, isn't", resp.Data["period"])
	}
	d.Set("period", period)
	return nil
}
