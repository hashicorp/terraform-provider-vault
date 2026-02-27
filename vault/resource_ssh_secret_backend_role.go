// Copyright IBM Corp. 2016, 2025
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

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
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
		consts.FieldName: {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Unique name for the role.",
		},
		consts.FieldBackend: {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		consts.FieldAllowBareDomains: {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		consts.FieldAllowHostCertificates: {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		consts.FieldAllowSubdomains: {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		consts.FieldAllowUserCertificates: {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		consts.FieldAllowUserKeyIDs: {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		consts.FieldAllowedCriticalOptions: {
			Type:     schema.TypeString,
			Optional: true,
		},
		consts.FieldAllowedDomainsTemplate: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		consts.FieldAllowedDomains: {
			Type:     schema.TypeString,
			Optional: true,
		},
		consts.FieldCIDRList: {
			Type:     schema.TypeString,
			Optional: true,
		},
		consts.FieldAllowedExtensions: {
			Type:     schema.TypeString,
			Optional: true,
		},
		consts.FieldDefaultExtensions: {
			Type:        schema.TypeMap,
			Optional:    true,
			Description: "Default extensions to include in SSH certificates. Only applicable for CA key type.",
			DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				// Suppress diff if key_type is not "ca" since Vault ignores this field for OTP
				keyType := strings.ToLower(d.Get(consts.FieldKeyType).(string))
				return keyType != consts.SSHKeyTypeCA
			},
		},
		consts.FieldDefaultExtensionsTemplate: {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Specifies if the default_extensions field supports templating. Only applicable for CA key type.",
			DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				// Suppress diff if key_type is not "ca" since Vault ignores this field for OTP
				keyType := strings.ToLower(d.Get(consts.FieldKeyType).(string))
				return keyType != consts.SSHKeyTypeCA
			},
		},
		consts.FieldDefaultCriticalOptions: {
			Type:     schema.TypeMap,
			Optional: true,
		},
		consts.FieldExcludeCIDRList: {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of CIDR blocks for which credentials cannot be created. Applicable for OTP and dynamic key types.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				// Suppress diff if key_type is "ca" since Vault ignores this field for CA roles
				// This field is applicable for OTP key type
				keyType := strings.ToLower(d.Get(consts.FieldKeyType).(string))
				return keyType == consts.SSHKeyTypeCA
			},
		},
		consts.FieldPort: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Specifies the port number for SSH connections (default 22). Applicable for OTP and dynamic key types.",
			DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				// Suppress diff if key_type is "ca" since Vault ignores this field for CA roles
				// This field is applicable for OTP key type
				keyType := strings.ToLower(d.Get(consts.FieldKeyType).(string))
				return keyType == consts.SSHKeyTypeCA
			},
		},
		consts.FieldAllowedUsersTemplate: {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
		consts.FieldAllowedUsers: {
			Type:     schema.TypeString,
			Optional: true,
		},
		consts.FieldDefaultUser: {
			Type:     schema.TypeString,
			Optional: true,
		},
		consts.FieldDefaultUserTemplate: {
			Type:     schema.TypeBool,
			Optional: true,
		},
		consts.FieldKeyIDFormat: {
			Type:     schema.TypeString,
			Optional: true,
		},
		consts.FieldKeyType: {
			Type:     schema.TypeString,
			Required: true,
		},
		consts.FieldAllowedUserKeyConfig: {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Set of allowed public key types and their relevant configuration",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					consts.FieldType: {
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
					consts.FieldLengths: {
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
		consts.FieldAlgorithmSigner: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldMaxTTL: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldTTL: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldNotBeforeDuration: {
			Type:        schema.TypeString,
			Description: "Specifies the duration by which to backdate the ValidAfter property. Uses duration format strings.",
			Optional:    true,
			Computed:    true,
		},
		consts.FieldAllowEmptyPrincipals: {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
	}

	return &schema.Resource{
		Create: sshSecretBackendRoleWrite,
		Read:   provider.ReadWrapper(sshSecretBackendRoleRead),
		Update: sshSecretBackendRoleWrite,
		Delete: sshSecretBackendRoleDelete,
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

	backend := d.Get(consts.FieldBackend).(string)
	name := d.Get(consts.FieldName).(string)

	path := sshRoleResourcePath(backend, name)

	data := map[string]interface{}{
		consts.FieldKeyType:               d.Get(consts.FieldKeyType).(string),
		consts.FieldAllowBareDomains:      d.Get(consts.FieldAllowBareDomains).(bool),
		consts.FieldAllowHostCertificates: d.Get(consts.FieldAllowHostCertificates).(bool),
		consts.FieldAllowSubdomains:       d.Get(consts.FieldAllowSubdomains).(bool),
		consts.FieldAllowUserCertificates: d.Get(consts.FieldAllowUserCertificates).(bool),
		consts.FieldAllowUserKeyIDs:       d.Get(consts.FieldAllowUserKeyIDs).(bool),
	}

	if v, ok := d.GetOk(consts.FieldAllowedCriticalOptions); ok {
		data[consts.FieldAllowedCriticalOptions] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldAllowedDomains); ok {
		data[consts.FieldAllowedDomains] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldCIDRList); ok {
		data[consts.FieldCIDRList] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldAllowedExtensions); ok {
		data[consts.FieldAllowedExtensions] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldDefaultExtensions); ok {
		data[consts.FieldDefaultExtensions] = v
	}

	if v, ok := d.GetOk(consts.FieldDefaultExtensionsTemplate); ok {
		data[consts.FieldDefaultExtensionsTemplate] = v.(bool)
	}

	if v, ok := d.GetOk(consts.FieldDefaultCriticalOptions); ok {
		data[consts.FieldDefaultCriticalOptions] = v
	}

	if v, ok := d.GetOk(consts.FieldExcludeCIDRList); ok {
		data[consts.FieldExcludeCIDRList] = strings.Join(util.TerraformSetToStringArray(v), ",")
	}

	// For port field , GetOk returns true even if value is only in state
	// Use GetRawConfig to check if port is actually set in the configuration
	if v, ok := d.GetOk(consts.FieldPort); ok {
		rawConfig := d.GetRawConfig()
		portAttr := rawConfig.GetAttr(consts.FieldPort)
		// Only send to Vault if port is explicitly set in config
		if !portAttr.IsNull() {
			data[consts.FieldPort] = v.(int)
		}
	}

	if v, ok := d.GetOk(consts.FieldAllowedUsersTemplate); ok {
		data[consts.FieldAllowedUsersTemplate] = v.(bool)
	}

	if v, ok := d.GetOk(consts.FieldAllowedUsers); ok {
		data[consts.FieldAllowedUsers] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldDefaultUser); ok {
		data[consts.FieldDefaultUser] = v.(string)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		if v, ok := d.GetOk(consts.FieldDefaultUserTemplate); ok {
			data[consts.FieldDefaultUserTemplate] = v.(bool)
		}

		data[consts.FieldAllowedDomainsTemplate] = d.Get(consts.FieldAllowedDomainsTemplate)
	}
	if provider.IsAPISupported(meta, provider.VaultVersion117) {
		data[consts.FieldAllowEmptyPrincipals] = d.Get(consts.FieldAllowEmptyPrincipals).(bool)
	}

	if v, ok := d.GetOk(consts.FieldKeyIDFormat); ok {
		data[consts.FieldKeyIDFormat] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldAlgorithmSigner); ok {
		data[consts.FieldAlgorithmSigner] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldMaxTTL); ok {
		data[consts.FieldMaxTTL] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldTTL); ok {
		data[consts.FieldTTL] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldNotBeforeDuration); ok {
		data[consts.FieldNotBeforeDuration] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldAllowedUserKeyConfig); ok {
		// post vault-1.10
		vals := make(map[string][]interface{})
		for _, m := range v.(*schema.Set).List() {
			val := m.(map[string]interface{})
			vals[val[consts.FieldType].(string)] = val[consts.FieldLengths].([]interface{})
		}
		data[consts.FieldAllowedUserKeyLengths] = vals
	}

	log.Printf("[DEBUG] Writing role %q on SSH backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing role %q for backend %q: %s", name, backend, err)
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

	if err := d.Set(consts.FieldName, name); err != nil {
		return err
	}

	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return err
	}

	fields := []string{
		consts.FieldKeyType, consts.FieldAllowBareDomains, consts.FieldAllowHostCertificates,
		consts.FieldAllowSubdomains, consts.FieldAllowUserCertificates, consts.FieldAllowUserKeyIDs,
		consts.FieldAllowedCriticalOptions, consts.FieldAllowedDomains,
		consts.FieldCIDRList, consts.FieldAllowedExtensions,
		consts.FieldDefaultCriticalOptions,
		consts.FieldAllowedUsersTemplate, consts.FieldAllowedUsers, consts.FieldDefaultUser,
		consts.FieldKeyIDFormat, consts.FieldMaxTTL, consts.FieldTTL, consts.FieldAlgorithmSigner,
		consts.FieldNotBeforeDuration,
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		fields = append(fields, []string{consts.FieldDefaultUserTemplate, consts.FieldAllowedDomainsTemplate}...)
	}
	if provider.IsAPISupported(meta, provider.VaultVersion117) {
		fields = append(fields, []string{consts.FieldAllowEmptyPrincipals}...)
	}

	// cannot be read from the API, potential for drift here:
	// - cidr_list
	// - allow_empty_principals
	for _, k := range fields {
		if err := d.Set(k, role.Data[k]); err != nil {
			return err
		}
	}

	// Handle port field
	// Vault returns port for OTP/dynamic roles (default 22 if not set)
	// For CA roles, Vault may not return port, so we set 0 to indicate unset
	// DiffSuppressFunc will prevent drift for CA roles with port in config
	if v, ok := role.Data[consts.FieldPort]; ok {
		if err := d.Set(consts.FieldPort, v); err != nil {
			return err
		}
	} else {
		// If Vault doesn't return port, set to 0
		// This ensures proper state management when port is removed from config
		if err := d.Set(consts.FieldPort, 0); err != nil {
			return err
		}
	}

	// Handle key_type specific fields - only set if returned by Vault
	// CA-specific: default_extensions, default_extensions_template
	// OTP-specific: exclude_cidr_list
	// DiffSuppressFunc prevents drift when fields are configured for wrong key_type
	if v, ok := role.Data[consts.FieldDefaultExtensions]; ok {
		if err := d.Set(consts.FieldDefaultExtensions, v); err != nil {
			return err
		}
	}

	if v, ok := role.Data[consts.FieldDefaultExtensionsTemplate]; ok {
		if err := d.Set(consts.FieldDefaultExtensionsTemplate, v); err != nil {
			return err
		}
	}

	if v, ok := role.Data[consts.FieldExcludeCIDRList].(string); ok && v != "" {
		cidrs := strings.Split(v, ",")
		// Trim whitespace from each CIDR
		for i, cidr := range cidrs {
			cidrs[i] = strings.TrimSpace(cidr)
		}
		if err := d.Set(consts.FieldExcludeCIDRList, cidrs); err != nil {
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

	// set the key configuration
	return d.Set(consts.FieldAllowedUserKeyConfig, keyConfigs)
}

func getSSHRoleKeyConfig(role *api.Secret) ([]map[string]interface{}, error) {
	keyConfigs := make([]map[string]interface{}, 0)

	l, ok := role.Data[consts.FieldAllowedUserKeyLengths].(map[string]interface{})
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
				"%s in vault response", v, consts.FieldAllowedUserKeyLengths)
		}

		keyConfigs = append(keyConfigs, map[string]interface{}{
			consts.FieldType:    keyType,
			consts.FieldLengths: lengths,
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
