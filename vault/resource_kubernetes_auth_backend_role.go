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
	kubernetesAuthBackendRoleBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/role/.+$")
	kubernetesAuthBackendRoleNameFromPathRegex    = regexp.MustCompile("^auth/.+/role/(.+)$")
)

func kubernetesAuthBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: kubernetesAuthBackendRoleCreate,
		Read:   kubernetesAuthBackendRoleRead,
		Update: kubernetesAuthBackendRoleUpdate,
		Delete: kubernetesAuthBackendRoleDelete,
		Exists: kubernetesAuthBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
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
				Required:    true,
			},
			"bound_service_account_namespaces": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of namespaces allowed to access this role. If set to \"*\" all namespaces are allowed, both this and bound_service_account_names can not be set to \"*\".",
				Required:    true,
			},
			"ttl": {
				Type:        schema.TypeInt,
				Description: "The TTL period of tokens issued using this role in seconds.",
				Optional:    true,
			},
			"max_ttl": {
				Type:        schema.TypeInt,
				Description: "The maximum allowed lifetime of tokens issued in seconds using this role.",
				Optional:    true,
			},
			"period": {
				Type:        schema.TypeInt,
				Description: "If set, indicates that the token generated using this role should never expire. The token should be renewed within the duration specified by this value. At each renewal, the token's TTL will be set to the value of this parameter.",
				Optional:    true,
			},
			"policies": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Policies to be set on tokens issued using this role.",
				Optional:    true,
			},
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
		},
	}
}

func kubernetesAuthBackendRolePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func kubernetesAuthBackendRoleNameFromPath(path string) (string, error) {
	if !kubernetesAuthBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := kubernetesAuthBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func kubernetesAuthBackendRoleBackendFromPath(path string) (string, error) {
	if !kubernetesAuthBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := kubernetesAuthBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func kubernetesAuthBackendRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role_name").(string)

	path := kubernetesAuthBackendRolePath(backend, role)

	log.Printf("[DEBUG] Writing Kubernetes auth backend role %q", path)

	iBoundServiceAccountNames := d.Get("bound_service_account_names").([]interface{})
	boundServiceAccountNames := make([]string, 0, len(iBoundServiceAccountNames))
	for _, iBoundServiceAccountName := range iBoundServiceAccountNames {
		boundServiceAccountNames = append(boundServiceAccountNames, iBoundServiceAccountName.(string))
	}

	iBoundServiceAccountNamespaces := d.Get("bound_service_account_namespaces").([]interface{})
	boundServiceAccountNamespaces := make([]string, 0, len(iBoundServiceAccountNamespaces))
	for _, iBoundServiceAccountNamespace := range iBoundServiceAccountNamespaces {
		boundServiceAccountNamespaces = append(boundServiceAccountNamespaces, iBoundServiceAccountNamespace.(string))
	}

	data := map[string]interface{}{}

	if len(boundServiceAccountNames) > 0 {
		data["bound_service_account_names"] = boundServiceAccountNames
	}
	if len(boundServiceAccountNamespaces) > 0 {
		data["bound_service_account_namespaces"] = boundServiceAccountNamespaces
	}

	if v, ok := d.GetOk("policies"); ok {
		iPolicies := v.([]interface{})
		policies := make([]string, 0, len(iPolicies))
		for _, iPolicy := range iPolicies {
			policies = append(policies, iPolicy.(string))
		}

		if len(policies) > 0 {
			data["policies"] = policies
		}
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

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing Kubernetes auth backend role %q: %s", path, err)
	}
	d.SetId(path)
	log.Printf("[DEBUG] Wrote Kubernetes auth backend role %q", path)

	return kubernetesAuthBackendRoleRead(d, meta)
}

func kubernetesAuthBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	backend, err := kubernetesAuthBackendRoleBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for Kubernetes auth backend role: %s", path, err)
	}

	role, err := kubernetesAuthBackendRoleNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for Kubernetes auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading Kubernetes auth backend role: %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading Kubernetes auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Kubernetes auth backend role: %q", path)
	if resp == nil {
		log.Printf("[WARN] Kubernetes auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set("backend", backend)
	d.Set("role_name", role)

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

	period, err := resp.Data["period"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected `period` %q to be a number, isn't", resp.Data["period"])
	}
	d.Set("period", period)

	return nil
}

func kubernetesAuthBackendRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Updating Kubernetes auth backend role %q", path)

	iBoundServiceAccountNames := d.Get("bound_service_account_names").([]interface{})
	boundServiceAccountNames := make([]string, 0, len(iBoundServiceAccountNames))
	for _, iBoundServiceAccountName := range iBoundServiceAccountNames {
		boundServiceAccountNames = append(boundServiceAccountNames, iBoundServiceAccountName.(string))
	}

	iBoundServiceAccountNamespaces := d.Get("bound_service_account_namespaces").([]interface{})
	boundServiceAccountNamespaces := make([]string, 0, len(iBoundServiceAccountNamespaces))
	for _, iBoundServiceAccountNamespace := range iBoundServiceAccountNamespaces {
		boundServiceAccountNamespaces = append(boundServiceAccountNamespaces, iBoundServiceAccountNamespace.(string))
	}

	iPolicies := d.Get("policies").([]interface{})
	policies := make([]string, 0, len(iPolicies))
	for _, iPolicy := range iPolicies {
		policies = append(policies, iPolicy.(string))
	}

	data := map[string]interface{}{
		"bound_service_account_names":      strings.Join(boundServiceAccountNames, ","),
		"bound_service_account_namespaces": strings.Join(boundServiceAccountNamespaces, ","),
		"policies":                         strings.Join(policies, ","),
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

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating Kubernetes auth backend role %q: %s", path, err)
	}

	// NOTE: Only `SetId` after it's successfully written in Vault
	d.SetId(path)

	log.Printf("[DEBUG] Updated Kubernetes auth backend role %q", path)

	return kubernetesAuthBackendRoleRead(d, meta)
}

func kubernetesAuthBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting Kubernetes auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil && !util.Is404(err) {
		return fmt.Errorf("error deleting Kubernetes auth backend role %q", path)
	} else if err != nil {
		log.Printf("[DEBUG] Kubernetes auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted Kubernetes auth backend role %q", path)

	return nil
}

func kubernetesAuthBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if Kubernetes auth backend role %q exists", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if Kubernetes auth backend role %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if Kubernetes auth backend role %q exists", path)

	return resp != nil, nil
}
