// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var approleAuthBackendRoleSecretIDIDRegex = regexp.MustCompile("^backend=(.+)::role=(.+)::accessor=(.+)$")

func approleAuthBackendRoleSecretIDResource(name string) *schema.Resource {
	return &schema.Resource{
		Create: approleAuthBackendRoleSecretIDCreate,
		Read:   provider.ReadWrapper(approleAuthBackendRoleSecretIDRead),
		Delete: approleAuthBackendRoleSecretIDDelete,
		Exists: approleAuthBackendRoleSecretIDExists,

		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role.",
				ForceNew:    true,
			},

			"secret_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The SecretID to be managed. If not specified, Vault auto-generates one.",
				ForceNew:    true,
				Sensitive:   true,
			},

			"cidr_list": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of CIDR blocks that can log in using the SecretID.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ForceNew: true,
			},

			consts.FieldMetadata: {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "JSON-encoded secret data to write.",
				StateFunc:    NormalizeDataJSONFunc(name),
				ValidateFunc: ValidateDataJSONFunc(name),
				ForceNew:     true,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					if old == "{}" && new == "" {
						return true
					}
					if old == "" && new == "{}" {
						return true
					}
					return false
				},
			},

			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "approle",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},

			"with_wrapped_accessor": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Use the wrapped secret-id accessor as the id of this resource. If false, a fresh secret-id will be regenerated whenever the wrapping token is expired or invalidated through unwrapping.",
				ForceNew:    true,
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique ID used to access this SecretID.",
			},

			"wrapping_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The TTL duration of the wrapped SecretID.",
			},

			"wrapping_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The wrapped SecretID token.",
				Sensitive:   true,
			},

			"wrapping_accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The wrapped SecretID accessor.",
			},
		},
	}
}

func approleAuthBackendRoleSecretIDCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	role := d.Get("role_name").(string)

	path := approleAuthBackendRolePath(backend, role) + "/secret-id"

	if _, ok := d.GetOk("secret_id"); ok {
		path = approleAuthBackendRolePath(backend, role) + "/custom-secret-id"
	}

	log.Printf("[DEBUG] Writing AppRole auth backend role SecretID %q", path)
	iCIDRs := d.Get("cidr_list").(*schema.Set).List()
	cidrs := make([]string, 0, len(iCIDRs))
	for _, iCIDR := range iCIDRs {
		cidrs = append(cidrs, iCIDR.(string))
	}

	data := map[string]interface{}{}
	if v, ok := d.GetOk("secret_id"); ok {
		data["secret_id"] = v.(string)
	}
	if len(cidrs) > 0 {
		data["cidr_list"] = strings.Join(cidrs, ",")
	}
	if v, ok := d.GetOk(consts.FieldMetadata); ok {
		name := "vault_approle_auth_backend_role_secret_id"
		result, err := normalizeDataJSON(v.(string))
		if err != nil {
			log.Printf("[ERROR] Failed to normalize JSON data %q, resource=%q, key=%q, err=%s",
				v, name, "metadata", err)
			return err
		}
		data["metadata"] = result
	} else {
		data["metadata"] = ""
	}
	withWrappedAccessor := d.Get("with_wrapped_accessor").(bool)

	wrappingTTL, wrapped := d.GetOk("wrapping_ttl")

	if wrapped {
		var err error

		if client, err = client.Clone(); err != nil {
			return fmt.Errorf("error cloning client: %w", err)
		}
		client.SetWrappingLookupFunc(func(_, _ string) string {
			return wrappingTTL.(string)
		})
	}

	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing AppRole auth backend role SecretID %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote AppRole auth backend role SecretID %q", path)

	var accessor string

	if wrapped {
		if withWrappedAccessor {
			accessor = resp.WrapInfo.WrappedAccessor
		} else {
			accessor = resp.WrapInfo.Accessor
		}
		d.Set("wrapping_token", resp.WrapInfo.Token)
		d.Set("wrapping_accessor", accessor)
	} else {
		accessor = resp.Data["secret_id_accessor"].(string)
		d.Set("secret_id", resp.Data["secret_id"])
		d.Set("accessor", accessor)
	}

	d.SetId(approleAuthBackendRoleSecretIDID(backend, role, accessor, wrapped, withWrappedAccessor))

	return approleAuthBackendRoleSecretIDRead(d, meta)
}

func approleAuthBackendRoleSecretIDRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	backend, role, accessor, wrapped, err := approleAuthBackendRoleSecretIDParseID(id)
	if err != nil {
		return fmt.Errorf("invalid ID %q for AppRole auth backend role SecretID: %s", id, err)
	}

	// If the ID is wrapped, there is no information available other than whether
	// the wrapping token is still valid, unless we are planning to re-use it.
	withWrappedAccessor := d.Get("with_wrapped_accessor").(bool)

	if wrapped && !withWrappedAccessor {
		valid, err := approleAuthBackendRoleSecretIDExists(d, meta)
		if err != nil {
			return err
		}
		if !valid {
			log.Printf("[WARN] AppRole auth backend role SecretID %q not found, removing from state", id)
			d.SetId("")
		}
		return nil
	}

	path := approleAuthBackendRolePath(backend, role) + "/secret-id-accessor/lookup"

	log.Printf("[DEBUG] Reading AppRole auth backend role SecretID %q from %q", id, path)
	resp, err := client.Logical().Write(path, map[string]interface{}{
		"secret_id_accessor": accessor,
	})
	if err != nil {
		// We need to check if the secret_id has expired
		if util.IsExpiredTokenErr(err) {
			return nil
		}
		return fmt.Errorf("error reading AppRole auth backend role SecretID %q: %s", id, err)
	}
	log.Printf("[DEBUG] Read AppRole auth backend role SecretID %q", id)
	if resp == nil {
		log.Printf("[WARN] AppRole auth backend role SecretID %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	var cidrs []string
	switch data := resp.Data["cidr_list"].(type) {
	case string:
		if data != "" {
			cidrs = strings.Split(data, ",")
		}
	case []interface{}:
		cidrs = make([]string, 0, len(data))
		for _, i := range data {
			cidrs = append(cidrs, i.(string))
		}
	case nil:
		cidrs = make([]string, 0)
	default:
		return fmt.Errorf("unknown type %T for cidr_list in response for SecretID %q", data, accessor)
	}

	metadata, err := json.Marshal(resp.Data["metadata"])
	if err != nil {
		return fmt.Errorf("error encoding metadata for SecretID %q to JSON: %s", id, err)
	}

	d.Set("backend", backend)
	d.Set("role_name", role)
	err = d.Set("cidr_list", cidrs)
	if err != nil {
		return fmt.Errorf("error setting cidr_list in state: %s", err)
	}
	d.Set(consts.FieldMetadata, string(metadata))
	d.Set("accessor", accessor)

	return nil
}

func approleAuthBackendRoleSecretIDDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()
	backend, role, accessor, wrapped, err := approleAuthBackendRoleSecretIDParseID(id)
	if err != nil {
		return fmt.Errorf("invalid ID %q for AppRole auth backend role SecretID: %s", id, err)
	}

	var path, accessorParam string

	if wrapped {
		path = "auth/token/revoke-accessor"
		accessorParam = "accessor"
	} else {
		path = approleAuthBackendRolePath(backend, role) + "/secret-id-accessor/destroy"
		accessorParam = "secret_id_accessor"
	}

	log.Printf("[DEBUG] Deleting AppRole auth backend role SecretID %q", id)
	_, err = client.Logical().Write(path, map[string]interface{}{
		accessorParam: accessor,
	})
	if err != nil {
		return fmt.Errorf("error deleting AppRole auth backend role SecretID %q", id)
	}
	log.Printf("[DEBUG] Deleted AppRole auth backend role SecretID %q", id)

	return nil
}

func approleAuthBackendRoleSecretIDExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	id := d.Id()

	backend, role, accessor, wrapped, err := approleAuthBackendRoleSecretIDParseID(id)
	if err != nil {
		return true, fmt.Errorf("invalid ID %q for AppRole auth backend role SecretID: %s", id, err)
	}

	if wrapped {
		_, err := client.Logical().Write("auth/token/lookup-accessor", map[string]interface{}{
			"accessor": accessor,
		})
		if err == nil {
			return true, nil
		} else if util.IsExpiredTokenErr(err) {
			return false, nil
		}
		return false, fmt.Errorf("error reading AppRole auth backend wrapped SecretID %q exists: %v", accessor, err)
	}

	path := approleAuthBackendRolePath(backend, role) + "/secret-id-accessor/lookup"

	log.Printf("[DEBUG] Checking if AppRole auth backend role SecretID %q exists", id)
	resp, err := client.Logical().Write(path, map[string]interface{}{
		"secret_id_accessor": accessor,
	})
	if err != nil {
		// We need to check if the secret_id has expired or if 404 was returned
		if util.IsExpiredTokenErr(err) || util.Is404(err) {
			return false, nil
		}
		return true, fmt.Errorf("error checking if AppRole auth backend role SecretID %q exists: %s", id, err)
	}
	log.Printf("[DEBUG] Checked if AppRole auth backend role SecretID %q exists", id)

	return resp != nil, nil
}

func approleAuthBackendRoleSecretIDID(backend, role, accessor string, wrapped bool, withWrappedAccessor bool) string {
	if wrapped && !withWrappedAccessor {
		accessor = "wrapped-" + accessor
	}
	return fmt.Sprintf("backend=%s::role=%s::accessor=%s", strings.Trim(backend, "/"), strings.Trim(role, "/"), accessor)
}

func approleAuthBackendRoleSecretIDParseID(id string) (backend, role, accessor string, wrapped bool, err error) {
	if !approleAuthBackendRoleSecretIDIDRegex.MatchString(id) {
		return "", "", "", false, fmt.Errorf("ID did not match pattern")
	}
	res := approleAuthBackendRoleSecretIDIDRegex.FindStringSubmatch(id)
	if len(res) != 4 {
		return "", "", "", false, fmt.Errorf("unexpected number of matches: %d", len(res))
	}

	backend, role, accessor = res[1], res[2], res[3]

	if strings.HasPrefix(accessor, "wrapped-") {
		accessor = strings.TrimPrefix(accessor, "wrapped-")
		wrapped = true
	}

	return
}
