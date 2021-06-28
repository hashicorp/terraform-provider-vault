package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
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

		// Deprecated
		"policies": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Description:   "Policies to be set on tokens issued using this role.",
			Deprecated:    "use `token_policies` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_policies"},
		},
		"ttl": {
			Type:          schema.TypeInt,
			Optional:      true,
			Description:   "Default number of seconds to set as the TTL for issued tokens and at renewal time.",
			ConflictsWith: []string{"token_ttl"},
			Deprecated:    "use `token_ttl` instead if you are running Vault >= 1.2",
		},
		"max_ttl": {
			Type:          schema.TypeInt,
			Optional:      true,
			Description:   "Number of seconds after which issued tokens can no longer be renewed.",
			Deprecated:    "use `token_max_ttl` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_max_ttl"},
		},
		"period": {
			Type:          schema.TypeInt,
			Optional:      true,
			Description:   "Number of seconds to set the TTL to for issued tokens upon renewal. Makes the token a periodic token, which will never expire as long as it is renewed before the TTL each period.",
			ConflictsWith: []string{"token_period"},
			Deprecated:    "use `token_period` instead if you are running Vault >= 1.2",
		},
		"num_uses": {
			Type:          schema.TypeInt,
			Optional:      true,
			Description:   "Number of times issued tokens can be used. Setting this to 0 or leaving it unset means unlimited uses.",
			Deprecated:    "use `token_num_uses` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_num_uses"},
		},
		"bound_cidrs": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of CIDRs valid as the source address for login requests. This value is also encoded into any resulting token.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Deprecated:    "use `token_bound_cidrs` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_bound_cidrs"},
		},
		"audience": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "Optional Audience claim to verify in the JWT.",
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{
		TokenBoundCidrsConflict: []string{"bound_cidrs"},
		TokenMaxTTLConflict:     []string{"max_ttl"},
		TokenNumUsesConflict:    []string{"num_uses"},
		TokenPeriodConflict:     []string{"period"},
		TokenPoliciesConflict:   []string{"policies"},
		TokenTTLConflict:        []string{"ttl"},
	})

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

	if policies, ok := d.GetOk("policies"); ok {
		data["policies"] = policies.(*schema.Set).List()
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

	// Check if the user is using the deprecated `num_uses`
	if _, deprecated := d.GetOk("num_uses"); deprecated {
		// Then we see if `token_num_uses` was set and unset it
		// Vault will still return `num_uses`
		if _, ok := d.GetOk("token_num_uses"); ok {
			d.Set("token_num_uses", nil)
		}

		if v, ok := resp.Data["num_uses"]; ok {
			d.Set("num_uses", v)
		}
	}

	// Check if the user is using the deprecated `bound_cidrs`
	if _, deprecated := d.GetOk("bound_cidrs"); deprecated {
		// Then we see if `token_bound_cidrs` was set and unset it
		// Vault will still return `bound_cidrs`
		if _, ok := d.GetOk("token_bound_cidrs"); ok {
			d.Set("token_bound_cidrs", nil)
		}

		if v, ok := resp.Data["bound_cidrs"]; ok {
			d.Set("bound_cidrs", v)
		}
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
