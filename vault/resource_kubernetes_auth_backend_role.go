package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/util"
)

var (
	kubernetesAuthBackendRoleBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/role/.+$")
	kubernetesAuthBackendRoleNameFromPathRegex    = regexp.MustCompile("^auth/.+/role/(.+)$")
)

func kubernetesAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role_name": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Name of the role.",
		},
		"bound_service_account_names": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Description: "List of service account names able to access this role. If set to `[\"*\"]` all names are allowed, both this and bound_service_account_namespaces can not be \"*\".",
			Required:    true,
		},
		"bound_service_account_namespaces": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Description: "List of namespaces allowed to access this role. If set to `[\"*\"]` all namespaces are allowed, both this and bound_service_account_names can not be set to \"*\".",
			Required:    true,
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
		"audience": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "Optional Audience claim to verify in the JWT.",
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		Create: kubernetesAuthBackendRoleCreate,
		Read:   kubernetesAuthBackendRoleRead,
		Update: kubernetesAuthBackendRoleUpdate,
		Delete: kubernetesAuthBackendRoleDelete,
		Exists: kubernetesAuthBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: fields,
	}
}

func kubernetesAuthBackendRolePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func kubernetesAuthBackendRoleUpdateFields(d *schema.ResourceData, data map[string]interface{}, create bool) {
	updateTokenFields(d, data, create)

	if boundServiceAccountNames, ok := d.GetOk("bound_service_account_names"); ok {
		data["bound_service_account_names"] = boundServiceAccountNames.(*schema.Set).List()
	}

	if boundServiceAccountNamespaces, ok := d.GetOk("bound_service_account_namespaces"); ok {
		data["bound_service_account_namespaces"] = boundServiceAccountNamespaces.(*schema.Set).List()
	}

	if create {
		if v, ok := d.GetOk("audience"); ok {
			data["audience"] = v.(string)
		}
	} else {
		if d.HasChange("audience") {
			data["audience"] = d.Get("audience").(string)
		}
	}
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

	data := map[string]interface{}{}
	kubernetesAuthBackendRoleUpdateFields(d, data, true)

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

	readTokenFields(d, resp)

	d.Set("backend", backend)
	d.Set("role_name", role)

	if v, ok := resp.Data["audience"]; ok {
		d.Set("audience", v)
	}

	for _, k := range []string{"bound_service_account_names", "bound_service_account_namespaces"} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for Kubernetes Auth Backend Role %q: %q", k, path, err)
			}
		}
	}

	return nil
}

func kubernetesAuthBackendRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Updating Kubernetes auth backend role %q", path)

	data := map[string]interface{}{}
	kubernetesAuthBackendRoleUpdateFields(d, data, false)

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
