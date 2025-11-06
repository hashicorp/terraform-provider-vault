// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
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
			Required:    true,
			Description: "List of service account names able to access this role. If set to `[\"*\"]` all names are allowed, both this and bound_service_account_namespaces can not be \"*\".",
		},
		"bound_service_account_namespaces": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Optional:    true,
			Description: "List of namespaces allowed to access this role. If set to `[\"*\"]` all namespaces are allowed, both this and bound_service_account_names can not be set to \"*\".",
		},
		"bound_service_account_namespace_selector": {
			Type:        schema.TypeString,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Optional:    true,
			Description: "A label selector for Kubernetes namespaces allowed to access this role. Accepts either a JSON or YAML object. The value should be of type LabelSelector. Currently, label selectors with matchExpressions are not supported. To use label selectors, Vault must have permission to read namespaces on the Kubernetes cluster. If set with bound_service_account_namespaces, the conditions are ORed.",
		},
		"backend": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
			Default:  "kubernetes",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
			Description: "Unique name of the kubernetes backend to configure.",
		},
		"audience": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "Optional Audience claim to verify in the JWT.",
		},
		"alias_name_source": {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "Configures how identity aliases are generated. Valid choices are: serviceaccount_uid, serviceaccount_name",
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		CreateContext: kubernetesAuthBackendRoleCreate,
		ReadContext:   provider.ReadContextWrapper(kubernetesAuthBackendRoleRead),
		UpdateContext: kubernetesAuthBackendRoleUpdate,
		DeleteContext: kubernetesAuthBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: fields,

		CustomizeDiff: func(ctx context.Context, d *schema.ResourceDiff, m interface{}) error {
			// At least one of bound_service_account_namespaces or bound_service_account_namespace_selector must be provided
			namespaces, hasNamespaces := d.GetOk("bound_service_account_namespaces")
			selector, hasSelector := d.GetOk("bound_service_account_namespace_selector")

			// Check if namespaces is empty set
			namespacesEmpty := !hasNamespaces || namespaces.(*schema.Set).Len() == 0
			// Check if selector is empty string
			selectorEmpty := !hasSelector || strings.TrimSpace(selector.(string)) == ""

			if namespacesEmpty && selectorEmpty {
				return fmt.Errorf("at least one of 'bound_service_account_namespaces' or 'bound_service_account_namespace_selector' must be provided")
			}

			return nil
		},
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

	if create {
		if boundServiceAccountNamespaces, ok := d.GetOk("bound_service_account_namespaces"); ok {
			data["bound_service_account_namespaces"] = boundServiceAccountNamespaces.(*schema.Set).List()
		}
	} else {
		// always send the current value from state on update so the backend preserves or clears it
		if v := d.Get("bound_service_account_namespaces"); v != nil {
			if s, ok := v.(*schema.Set); ok {
				data["bound_service_account_namespaces"] = s.List()
			} else {
				// fallback: attempt to set as-is
				data["bound_service_account_namespaces"] = v
			}
		} else {
			data["bound_service_account_namespaces"] = []interface{}{}
		}
	}

	// Always set bound_service_account_namespace_selector to ensure proper clearing on updates
	if create {
		if boundServiceAccountNamespaceSelector, ok := d.GetOk("bound_service_account_namespace_selector"); ok {
			data["bound_service_account_namespace_selector"] = boundServiceAccountNamespaceSelector.(string)
		}
	} else {
		// always send the current value from state on update so the backend preserves or clears it
		if v := d.Get("bound_service_account_namespace_selector"); v != nil {
			data["bound_service_account_namespace_selector"] = v.(string)
		} else {
			data["bound_service_account_namespace_selector"] = ""
		}
	}

	params := []string{"audience", "alias_name_source"}
	for _, k := range params {
		if create {
			if v, ok := d.GetOk(k); ok {
				data[k] = v
			}
		} else {
			if d.HasChange(k) {
				data[k] = d.Get(k)
			}
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

func kubernetesAuthBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	role := d.Get("role_name").(string)

	path := kubernetesAuthBackendRolePath(backend, role)

	log.Printf("[DEBUG] Writing Kubernetes auth backend role %q", path)

	data := map[string]interface{}{}
	kubernetesAuthBackendRoleUpdateFields(d, data, true)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error writing Kubernetes auth backend role %q: %s", path, err)
	}
	d.SetId(path)
	log.Printf("[DEBUG] Wrote Kubernetes auth backend role %q", path)

	return kubernetesAuthBackendRoleRead(ctx, d, meta)
}

func kubernetesAuthBackendRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	backend, err := kubernetesAuthBackendRoleBackendFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for Kubernetes auth backend role: %s", path, err)
	}

	role, err := kubernetesAuthBackendRoleNameFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for Kubernetes auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading Kubernetes auth backend role: %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading Kubernetes auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Kubernetes auth backend role: %q", path)
	if resp == nil {
		log.Printf("[WARN] Kubernetes auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("backend", backend); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("role_name", role); err != nil {
		return diag.FromErr(err)
	}

	params := []string{"bound_service_account_names", "bound_service_account_namespaces", "bound_service_account_namespace_selector", "audience", "alias_name_source"}
	for _, k := range params {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error reading %s for Kubernetes Auth Backend Role %q: %q", k, path, err)
			}
		}
	}

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func kubernetesAuthBackendRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Updating Kubernetes auth backend role %q", path)

	data := map[string]interface{}{}
	kubernetesAuthBackendRoleUpdateFields(d, data, false)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error updating Kubernetes auth backend role %q: %s", path, err)
	}

	// NOTE: Only `SetId` after it's successfully written in Vault
	d.SetId(path)

	log.Printf("[DEBUG] Updated Kubernetes auth backend role %q", path)

	return kubernetesAuthBackendRoleRead(ctx, d, meta)
}

func kubernetesAuthBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting Kubernetes auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil && !util.Is404(err) {
		return diag.Errorf("error deleting Kubernetes auth backend role %q", path)
	} else if err != nil {
		log.Printf("[DEBUG] Kubernetes auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted Kubernetes auth backend role %q", path)

	return nil
}
