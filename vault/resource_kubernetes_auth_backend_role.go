package vault

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func kubernetesAuthBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: kubernetesAuthBackendRoleWrite,
		Read:   kubernetesAuthBackendRoleRead,
		Update: kubernetesAuthBackendRoleWrite,
		Delete: kubernetesAuthBackendRoleDelete,
		Exists: kubernetesAuthBackendRoleExists,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path to the Kubernetes auth backend",
			},

			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.Contains(value, "/") {
						errs = append(errs, errors.New("role name cannot contain '/'"))
					}
					return
				},
			},

			"service_accounts": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "Service accounts able to access this role",
				Set:         schema.HashString,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			"namespaces": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "Namespaces able to access this role",
				Set:         schema.HashString,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Lifetime of tokens issued by this role by default",
			},

			"max_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Maximum lifetime of tokens issued by this role",
			},

			"period": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Indicates that the token issued by this role should never expire; on renewal the TTL of the token will be set to this value",
			},

			"policies": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Policies assigned to tokens issued by this role",
				Set:         schema.HashString,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func kubernetesAuthBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	name := d.Get("name").(string)
	ttl := d.Get("ttl").(string)
	maxTTL := d.Get("max_ttl").(string)
	period := d.Get("period").(string)

	var serviceAccountsArray []string
	if serviceAccounts, ok := d.GetOk("service_accounts"); ok {
		serviceAccountsArray = toStringArray(serviceAccounts.(*schema.Set).List())
	} else {
		serviceAccountsArray = []string{}
	}

	var namespacesArray []string
	if namespaces, ok := d.GetOk("namespaces"); ok {
		namespacesArray = toStringArray(namespaces.(*schema.Set).List())
	} else {
		namespacesArray = []string{}
	}

	var policiesArray []string
	if policies, ok := d.GetOk("policies"); ok {
		policiesArray = toStringArray(policies.(*schema.Set).List())
	} else {
		policiesArray = []string{}
	}

	log.Printf("[DEBUG] Writing Kubernetes auth backend %q role %q", path, name)
	if err := updateKubernetesRole(client, path, kubernetesRole{
		Name:            name,
		ServiceAccounts: serviceAccountsArray,
		Namespaces:      namespacesArray,
		TTL:             ttl,
		MaxTTL:          maxTTL,
		Period:          period,
		Policies:        policiesArray,
	}); err != nil {
		return fmt.Errorf("Error writing Kubernetes auth backend %q role %q: %s", path, name, err)
	}

	d.SetId(fmt.Sprintf("%s/%s", path, name))

	return kubernetesAuthBackendRoleRead(d, meta)
}

func kubernetesAuthBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	name := d.Get("name").(string)

	log.Printf("[DEBUG] Reading Kubernetes auth backend %q role %q", path, name)
	role, err := readKubernetesRole(client, path, name)
	if err != nil {
		return fmt.Errorf("Error reading Kubernetes auth backend %q role %q: %s", path, name, err)
	}

	if role != nil {
		if err := d.Set("service_accounts", role.ServiceAccounts); err != nil {
			return err
		}
		if err := d.Set("namespaces", role.Namespaces); err != nil {
			return err
		}
		if err := d.Set("ttl", role.TTL); err != nil {
			return err
		}
		if err := d.Set("max_ttl", role.MaxTTL); err != nil {
			return err
		}
		if err := d.Set("period", role.Period); err != nil {
			return err
		}
		if err := d.Set("policies", role.Policies); err != nil {
			return err
		}
	} else {
		// Resource does not exist, so clear ID
		d.SetId("")
	}

	return nil
}

func kubernetesAuthBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	name := d.Get("name").(string)

	log.Printf("[DEBUG] Removing Kubernetes auth backend %q role %q", path, name)
	if _, err := client.Logical().Delete(kubernetesRoleEndpoint(path, name)); err != nil {
		return fmt.Errorf("Error removing Kubernetes auth backend %q role %q: %s", path, name, err)
	}

	d.SetId("")

	return nil
}

func kubernetesAuthBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	name := d.Get("name").(string)

	log.Printf("[DEBUG] Checking if Kubernetes auth backend %q role %q exists", path, name)
	resp, err := client.Logical().Read(fmt.Sprintf("auth/%s/role/%s", path, name))
	if err != nil {
		return true, fmt.Errorf("Error checking if Kubernetes auth backend %q role %q exists: %s", path, name, err)
	}

	return resp != nil, nil
}
