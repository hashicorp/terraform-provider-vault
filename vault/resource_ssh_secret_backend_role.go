// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	sshSecretBackendRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/roles/.+$")
	sshSecretBackendRoleNameFromPathRegex    = regexp.MustCompile("^.+/roles/(.+$)")
	sshRoleSupportPublicKeyTypes             = []string{
		"rsa", "ecdsa", "ec", "dsa", "ed25519",
		ssh.KeyAlgoRSA, ssh.KeyAlgoDSA, ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	}
)

func sshSecretBackendRoleResource() *schema.Resource {
	s := map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Unique name for the role.",
		},
		"backend": {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		"allow_bare_domains": {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		"allow_host_certificates": {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		"allow_subdomains": {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		"allow_user_certificates": {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		"allow_user_key_ids": {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		"allowed_critical_options": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"allowed_domains_template": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"allowed_domains": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"cidr_list": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"allowed_extensions": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"default_extensions": {
			Type:     schema.TypeMap,
			Optional: true,
		},
		"default_critical_options": {
			Type:     schema.TypeMap,
			Optional: true,
		},
		"allowed_users_template": {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		"allowed_users": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"default_user": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"default_user_template": {
			Type:     schema.TypeBool,
			Optional: true,
		},
		"key_id_format": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"key_type": {
			Type:     schema.TypeString,
			Required: true,
		},
		"allowed_user_key_lengths": {
			Type:          schema.TypeMap,
			Optional:      true,
			ConflictsWith: []string{"allowed_user_key_config"},
			Deprecated:    "Set in allowed_user_key_config",
			Elem: &schema.Schema{
				Type: schema.TypeInt,
			},
		},
		"allowed_user_key_config": {
			Type:          schema.TypeSet,
			Optional:      true,
			Description:   "Set of allowed public key types and their relevant configuration",
			ConflictsWith: []string{"allowed_user_key_lengths"},
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"type": {
						Required: true,
						Type:     schema.TypeString,
						Description: fmt.Sprintf("Key type, choices:\n%s",
							strings.Join(sshRoleSupportPublicKeyTypes, ", ")),
						ValidateDiagFunc: func(i interface{}, path cty.Path) diag.Diagnostics {
							v := i.(string)
							for _, allowed := range sshRoleSupportPublicKeyTypes {
								if v == allowed {
									return nil
								}
							}

							return []diag.Diagnostic{
								{
									Severity: diag.Error,
									Summary:  fmt.Sprintf("Unsupported key type %q specified", v),
									Detail: fmt.Sprintf(
										"Supported key types are:\n%s",
										strings.Join(sshRoleSupportPublicKeyTypes, ", ")),
									AttributePath: path,
								},
							}
						},
					},
					"lengths": {
						Description: "List of allowed key lengths, vault-1.10 and above",
						Required:    true,
						Type:        schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeInt,
						},
					},
				},
			},
		},
		"algorithm_signer": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"max_ttl": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"ttl": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"not_before_duration": {
			Type:        schema.TypeString,
			Description: "Specifies the duration by which to backdate the ValidAfter property. Uses duration format strings.",
			Optional:    true,
			Computed:    true,
		},
	}

	return &schema.Resource{
		Create: sshSecretBackendRoleWrite,
		Read:   provider.ReadWrapper(sshSecretBackendRoleRead),
		Update: sshSecretBackendRoleWrite,
		Delete: sshSecretBackendRoleDelete,
		Exists: sshSecretBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: s,
	}
}

func sshSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := sshRoleResourcePath(backend, name)

	data := map[string]interface{}{
		"key_type":                d.Get("key_type").(string),
		"allow_bare_domains":      d.Get("allow_bare_domains").(bool),
		"allow_host_certificates": d.Get("allow_host_certificates").(bool),
		"allow_subdomains":        d.Get("allow_subdomains").(bool),
		"allow_user_certificates": d.Get("allow_user_certificates").(bool),
		"allow_user_key_ids":      d.Get("allow_user_key_ids").(bool),
	}

	if v, ok := d.GetOk("allowed_critical_options"); ok {
		data["allowed_critical_options"] = v.(string)
	}

	if v, ok := d.GetOk("allowed_domains"); ok {
		data["allowed_domains"] = v.(string)
	}

	if v, ok := d.GetOk("cidr_list"); ok {
		data["cidr_list"] = v.(string)
	}

	if v, ok := d.GetOk("allowed_extensions"); ok {
		data["allowed_extensions"] = v.(string)
	}

	if v, ok := d.GetOk("default_extensions"); ok {
		data["default_extensions"] = v
	}

	if v, ok := d.GetOk("default_critical_options"); ok {
		data["default_critical_options"] = v
	}

	if v, ok := d.GetOk("allowed_users_template"); ok {
		data["allowed_users_template"] = v.(bool)
	}

	if v, ok := d.GetOk("allowed_users"); ok {
		data["allowed_users"] = v.(string)
	}

	if v, ok := d.GetOk("default_user"); ok {
		data["default_user"] = v.(string)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		if v, ok := d.GetOk("default_user_template"); ok {
			data["default_user_template"] = v.(bool)
		}

		data["allowed_domains_template"] = d.Get("allowed_domains_template")
	}

	if v, ok := d.GetOk("key_id_format"); ok {
		data["key_id_format"] = v.(string)
	}

	if v, ok := d.GetOk("algorithm_signer"); ok {
		data["algorithm_signer"] = v.(string)
	}

	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(string)
	}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(string)
	}

	if v, ok := d.GetOk("not_before_duration"); ok {
		data["not_before_duration"] = v.(string)
	}

	var isUserKeyConfig bool
	if v, ok := d.GetOk("allowed_user_key_config"); ok {
		// post vault-1.10
		isUserKeyConfig = true
		vals := make(map[string][]interface{})
		for _, m := range v.(*schema.Set).List() {
			val := m.(map[string]interface{})
			vals[val["type"].(string)] = val["lengths"].([]interface{})
		}
		data["allowed_user_key_lengths"] = vals
	} else if v, ok := d.GetOk("allowed_user_key_lengths"); ok {
		// pre vault-1.10
		data["allowed_user_key_lengths"] = v
	}

	log.Printf("[DEBUG] Writing role %q on SSH backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		// in the case where vault does not support a list of key lengths,
		// we fall back to map[string]interface{}.
		// TODO: once we support Vault API version semantics,
		// we can use it rather than checking the error string.
		if isUserKeyConfig && strings.Contains(err.Error(),
			"error processing allowed_user_key_lengths") {
			keyConfigs := make(map[string]interface{}, 0)
			for k, v := range data["allowed_user_key_lengths"].(map[string][]interface{}) {
				var l interface{}
				count := len(v)
				if count > 0 {
					l = v[0]
				}
				if count > 1 {
					log.Printf("[WARN] Only single key lengths are supported by the Vault server, "+
						"but %d are configured for key type %q", count, k)
				}
				keyConfigs[k] = l
			}
			data["allowed_user_key_lengths"] = keyConfigs
			_, err = client.Logical().Write(path, data)
		}

		if err != nil {
			return fmt.Errorf("error writing role %q for backend %q: %s", name, backend, err)
		}
	}
	log.Printf("[DEBUG] Wrote role %q on SSH backend %q", name, backend)

	d.SetId(path)

	return sshSecretBackendRoleRead(d, meta)
}

func sshSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	name, err := sshSecretBackendRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing ssh role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid role ID %q: %s", path, err)
	}

	backend, err := sshSecretBackendRoleBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing ssh role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading role from %q", path)
	role, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read role from %q", path)
	if role == nil {
		log.Printf("[WARN] Role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := d.Set("name", name); err != nil {
		return err
	}

	if err := d.Set("backend", backend); err != nil {
		return err
	}

	fields := []string{
		"key_type", "allow_bare_domains", "allow_host_certificates",
		"allow_subdomains", "allow_user_certificates", "allow_user_key_ids",
		"allowed_critical_options", "allowed_domains",
		"cidr_list", "allowed_extensions", "default_extensions",
		"default_critical_options", "allowed_users_template",
		"allowed_users", "default_user", "key_id_format",
		"max_ttl", "ttl", "algorithm_signer", "not_before_duration",
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		fields = append(fields, []string{"default_user_template", "allowed_domains_template"}...)
	}

	// cidr_list cannot be read from the API
	// potential for drift here
	for _, k := range fields {
		if err := d.Set(k, role.Data[k]); err != nil {
			return err
		}
	}

	if err := setSSHRoleKeyConfig(d, role); err != nil {
		return err
	}

	return nil
}

func setSSHRoleKeyConfig(d *schema.ResourceData, role *api.Secret) error {
	keyConfigs, err := getSSHRoleKeyConfig(role)
	if err != nil {
		return err
	}

	newField := "allowed_user_key_config"
	legacyField := "allowed_user_key_lengths"
	// work around to support the allowed_user_key_lengths with Vault 1.10+
	if _, ok := d.GetOk(legacyField); ok {
		v := make(map[string]interface{})
		for _, val := range keyConfigs {
			keyType := val["type"].(string)
			lengths := val["lengths"].([]interface{})
			var l interface{}
			count := len(lengths)
			if count > 0 {
				l = lengths[0]
			}

			if count > 1 {
				log.Printf("[WARN] Vault 1.10+ returned more than one "+
					"key length for key type %q, specify key lengths in a "+
					"%q block instead of %q with values %v",
					newField, keyType, legacyField, lengths)
			}

			v[keyType] = l
		}

		return d.Set(legacyField, v)
	} else {
		// set the key configuration
		return d.Set(newField, keyConfigs)
	}
}

func getSSHRoleKeyConfig(role *api.Secret) ([]map[string]interface{}, error) {
	keyConfigs := make([]map[string]interface{}, 0)

	l, ok := role.Data["allowed_user_key_lengths"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	for keyType, i := range l {
		var lengths []interface{}
		switch v := i.(type) {
		// vault-1.10+ response
		case []interface{}:
			lengths = v
		// vault-1.9- response
		case interface{}:
			lengths = append(lengths, v)
		default:
			return nil, fmt.Errorf("unexpected value type %T returned for "+
				"allowed_user_key_lengths in vault response", v)
		}

		keyConfigs = append(keyConfigs, map[string]interface{}{
			"type":    keyType,
			"lengths": lengths,
		})
	}

	return keyConfigs, nil
}

func sshSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Deleting role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted role %q", path)

	return nil
}

func sshSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)
	role, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return role != nil, nil
}

func sshRoleResourcePath(backend, name string) string {
	return strings.Trim(backend, "/") + "/roles/" + strings.Trim(name, "/")
}

func sshSecretBackendRoleNameFromPath(path string) (string, error) {
	if !sshSecretBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := sshSecretBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func sshSecretBackendRoleBackendFromPath(path string) (string, error) {
	if !sshSecretBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := sshSecretBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
