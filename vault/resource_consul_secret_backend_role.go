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

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	consulSecretBackendRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/roles/.+$")
	consulSecretBackendRoleNameFromPathRegex    = regexp.MustCompile("^.+/roles/(.+$)")
)

func consulSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: consulSecretBackendRoleWrite,
		ReadContext:   provider.ReadContextWrapper(consulSecretBackendRoleRead),
		UpdateContext: consulSecretBackendRoleWrite,
		DeleteContext: consulSecretBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of an existing role against which to create this Consul credential",
			},
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The path of the Consul Secret Backend the role belongs to.",
			},
			"policies": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of Consul policies to associate with this role",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ConflictsWith: []string{"consul_policies"},
			},
			"consul_policies": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of Consul policies to associate with this role",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ConflictsWith: []string{"policies"},
			},
			"consul_roles": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: `Set of Consul roles to attach to the token. Applicable for Vault 1.10+ with Consul 1.5+`,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"service_identities": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: `Set of Consul service identities to attach to
				the token. Applicable for Vault 1.11+ with Consul 1.5+`,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"node_identities": {
				Type:     schema.TypeSet,
				Optional: true,
				Description: `Set of Consul node identities to attach to
				the token. Applicable for Vault 1.11+ with Consul 1.8+`,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"consul_namespace": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "The Consul namespace that the token will be " +
					"created in. Applicable for Vault 1.10+ and Consul 1.7+",
			},
			"partition": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "The Consul admin partition that the token will be " +
					"created in. Applicable for Vault 1.10+ and Consul 1.11+",
			},
			"max_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum TTL for leases associated with this role, in seconds.",
				Default:     0,
			},
			"ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Specifies the TTL for this role.",
				Default:     0,
			},
			"local": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Indicates that the token should not be replicated globally and instead be local to the current datacenter.",
				Default:     false,
			},
		},
	}
}

func consulSecretBackendRoleGetBackend(d *schema.ResourceData) string {
	if v, ok := d.GetOk("backend"); ok {
		return v.(string)
	} else if v, ok := d.GetOk(consts.FieldPath); ok {
		return v.(string)
	} else {
		return ""
	}
}

func consulSecretBackendRoleWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get("name").(string)

	backend := consulSecretBackendRoleGetBackend(d)
	if backend == "" {
		return diag.Errorf("no backend specified for Consul secret backend role %s", name)
	}

	path := consulSecretBackendRolePath(backend, name)

	// This loads either the consul_policies or policies field, depending on which the
	// user provided, and then stores it under the appropriate key in the data.
	var policies []interface{}
	if v, ok := d.GetOk("policies"); ok {
		policies = v.([]interface{})
	} else if v, ok := d.GetOk("consul_policies"); ok {
		policies = v.(*schema.Set).List()
	}

	roles := d.Get("consul_roles").(*schema.Set).List()
	serviceIdentities := d.Get("service_identities").(*schema.Set).List()
	nodeIdentities := d.Get("node_identities").(*schema.Set).List()

	data := map[string]interface{}{
		"consul_roles":       roles,
		"service_identities": serviceIdentities,
		"node_identities":    nodeIdentities,
	}

	useAPIVer1 := provider.IsAPISupported(meta, provider.VaultVersion111)

	if useAPIVer1 {
		data["consul_policies"] = policies
	} else {
		data["policies"] = policies
	}

	params := []string{
		"max_ttl",
		"ttl",
		"local",
		"consul_namespace",
		"partition",
	}
	for _, k := range params {
		if v, ok := d.GetOkExists(k); ok {
			data[k] = v
		}
	}

	log.Printf("[DEBUG] Configuring Consul secrets backend role at %q", path)

	if _, err := client.Logical().Write(path, data); err != nil {
		return diag.Errorf("error writing role configuration for %q: %s", path, err)
	}

	d.SetId(path)
	return consulSecretBackendRoleRead(ctx, d, meta)
}

func consulSecretBackendRoleRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	upgradeOldID(d)

	path := d.Id()
	name, err := consulSecretBackendRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing consul role %q because its ID is invalid", path)
		d.SetId("")
		return diag.Errorf("invalid role ID %q: %s", path, err)
	}

	backend, err := consulSecretBackendRoleBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing consul role %q because its ID is invalid", path)
		d.SetId("")
		return diag.Errorf("invalid role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading Consul secrets backend role at %q", path)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading role configuration for %q: %s", path, err)
	}

	if secret == nil {
		log.Printf("[WARN] ConsulSecretBackendRole %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	data := secret.Data
	if err := d.Set("name", name); err != nil {
		return diag.FromErr(err)
	}
	var pathKey string
	if _, ok := d.GetOk(consts.FieldPath); ok {
		pathKey = consts.FieldPath
	} else {
		pathKey = "backend"
	}
	if err := d.Set(pathKey, backend); err != nil {
		return diag.FromErr(err)
	}

	// map request params to schema fields
	params := map[string]string{
		"max_ttl":            "max_ttl",
		"ttl":                "ttl",
		"local":              "local",
		"consul_roles":       "consul_roles",
		"consul_namespace":   "consul_namespace",
		"partition":          "partition",
		"service_identities": "service_identities",
		"node_identities":    "node_identities",
	}

	// Check whether Vault will return consul_policies or policies based on its version.
	useAPIVer1 := provider.IsAPISupported(meta, provider.VaultVersion111)

	// Determine to set either policies or consul_policies depending on the Vault version:
	// * Vault version < 1.11: Use policies
	// * Vault version >= 1.11: Use consul_policies
	policiesField := "consul_policies"
	if !useAPIVer1 {
		policiesField = "policies"
	}

	// If the user specified policies, store the result from Vault under that key.
	// Otherwise, always store under the key consul_policies.
	if _, ok := d.GetOk("policies"); ok {
		params[policiesField] = "policies"
	} else {
		params[policiesField] = "consul_policies"
	}

	for k, v := range params {
		val, ok := data[k]
		if !ok {
			switch k {
			// TODO case this by Vault version (vault-1.10+ request params)
			case "consul_roles", "consul_namespace", "partition":
				continue
			// TODO case this by Vault version (vault-1.11+ request params)
			case "service_identities", "node_identities":
				continue
			}
		}
		if err := d.Set(v, val); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func consulSecretBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting Consul backend role at %q", path)

	if _, err := client.Logical().Delete(path); err != nil {
		return diag.Errorf("error deleting Consul backend role at %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted Consul backend role at %q", path)
	return nil
}

func upgradeOldID(d *schema.ResourceData) {
	// Upgrade old "{backend},{name}" ID format
	id := d.Id()
	s := strings.Split(id, ",")
	if len(s) == 2 {
		backend := s[0]
		name := s[1]
		path := consulSecretBackendRolePath(backend, name)
		log.Printf("[DEBUG] Upgrading old ID %s to %s", id, path)
		d.SetId(path)
	}
}

func consulSecretBackendRolePath(backend, name string) string {
	return strings.Trim(backend, "/") + "/roles/" + name
}

func consulSecretBackendRoleNameFromPath(path string) (string, error) {
	if !consulSecretBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := consulSecretBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func consulSecretBackendRoleBackendFromPath(path string) (string, error) {
	if !consulSecretBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := consulSecretBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
