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
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/pki"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	pkiSecretBackendRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/roles/.+$")
	pkiSecretBackendRoleNameFromPathRegex    = regexp.MustCompile("^.+/roles/(.+)$")
)

func pkiSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendRoleCreate,
		Read:   ReadWrapper(pkiSecretBackendRoleRead),
		Update: pkiSecretBackendRoleUpdate,
		Delete: pkiSecretBackendRoleDelete,
		Exists: pkiSecretBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the PKI secret backend the resource belongs to.",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the role.",
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The TTL.",
			},
			"max_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The maximum TTL.",
			},
			"allow_localhost": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow certificates for localhost.",
				Default:     true,
			},
			"allowed_domains": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The domains of the role.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_domains_template": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to indicate that `allowed_domains` specifies a template expression (e.g. {{identity.entity.aliases.<mount accessor>.name}})",
				Default:     false,
			},
			"allow_bare_domains": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow certificates matching the actual domain.",
				Default:     false,
			},
			"allow_subdomains": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow certificates matching subdomains.",
				Default:     false,
			},
			"allow_glob_domains": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow names containing glob patterns.",
				Default:     false,
			},
			"allow_any_name": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow any name",
				Default:     false,
			},
			"allow_wildcard_certificates": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow wildcard certificates",
				Default:     true,
			},
			"enforce_hostnames": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow only valid host names",
				Default:     true,
			},
			"allow_ip_sans": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow IP SANs",
				Default:     true,
			},
			"allowed_uri_sans": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "Defines allowed URI SANs",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"allowed_other_sans": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "Defines allowed custom SANs",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"server_flag": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to specify certificates for server use.",
				Default:     true,
			},
			"client_flag": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to specify certificates for client use.",
				Default:     true,
			},
			"code_signing_flag": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to specify certificates for code signing use.",
				Default:     false,
			},
			"email_protection_flag": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to specify certificates for email protection use.",
				Default:     false,
			},
			"key_type": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Description:  "The generated key type.",
				ValidateFunc: validation.StringInSlice([]string{"rsa", "ec", "ed25519", "any"}, false),
				Default:      "rsa",
			},
			"key_bits": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "The number of bits of generated keys.",
				Default:     2048,
			},
			"key_usage": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "Specify the allowed key usage constraint on issued certificates.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ext_key_usage": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "Specify the allowed extended key usage constraint on issued certificates.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"use_csr_common_name": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to use the CN in the CSR.",
				Default:     true,
			},
			"use_csr_sans": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to use the SANs in the CSR.",
				Default:     true,
			},
			"ou": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The organization unit of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"organization": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The organization of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"country": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The country of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"locality": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The locality of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"province": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The province of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"street_address": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The street address of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"postal_code": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The postal code of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"generate_lease": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to generate leases with certificates.",
				Default:     false,
			},
			"no_store": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to not store certificates in the storage backend.",
				Default:     false,
			},
			"require_cn": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to force CN usage.",
				Default:     true,
			},
			"policy_identifiers": {
				Type:          schema.TypeList,
				Required:      false,
				Optional:      true,
				Description:   "Specify the list of allowed policies OIDs.",
				ConflictsWith: []string{"policy_identifier"},
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"policy_identifier": {
				Type:          schema.TypeSet,
				Optional:      true,
				Description:   "Policy identifier block; can only be used with Vault 1.11+",
				ConflictsWith: []string{"policy_identifiers"},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"oid": {
							Type:        schema.TypeString,
							Required:    true,
							Optional:    false,
							Description: "OID",
						},
						"cps": {
							Type:        schema.TypeString,
							Required:    false,
							Optional:    true,
							Description: "Optional CPS URL",
						},
						"notice": {
							Type:        schema.TypeString,
							Required:    false,
							Optional:    true,
							Description: "Optional notice",
						},
					},
				},
			},
			"basic_constraints_valid_for_non_ca": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to mark basic constraints valid when issuing non-CA certificates.",
				Default:     false,
			},
			"not_before_duration": {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Computed:     true,
				Description:  "Specifies the duration by which to backdate the NotBefore property.",
				ValidateFunc: provider.ValidateDuration,
			},
			"allowed_serial_numbers": {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "Defines allowed Subject serial numbers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func pkiSecretBackendRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := pkiSecretBackendRolePath(backend, name)

	log.Printf("[DEBUG] Writing PKI secret backend role %q", path)

	// TODO: selectively configure the engine by replacing all of the d.Get()
	// calls with d.GetOk()
	// The current approach is inconsistent with the majority of the other resources.
	// It also sets a bad precedent for contributors.
	iAllowedDomains := d.Get("allowed_domains").([]interface{})
	allowedDomains := make([]string, 0, len(iAllowedDomains))
	for _, iAllowedDomain := range iAllowedDomains {
		allowedDomains = append(allowedDomains, iAllowedDomain.(string))
	}

	iKeyUsage := d.Get("key_usage").([]interface{})
	keyUsage := make([]string, 0, len(iKeyUsage))
	for _, iUsage := range iKeyUsage {
		keyUsage = append(keyUsage, iUsage.(string))
	}

	iExtKeyUsage := d.Get("ext_key_usage").([]interface{})
	extKeyUsage := make([]string, 0, len(iExtKeyUsage))
	for _, iUsage := range iExtKeyUsage {
		extKeyUsage = append(extKeyUsage, iUsage.(string))
	}

	iAllowedSerialNumbers := d.Get("allowed_serial_numbers").([]interface{})
	allowedSerialNumbers := make([]string, 0, len(iAllowedSerialNumbers))
	for _, iSerialNumber := range iAllowedSerialNumbers {
		allowedSerialNumbers = append(allowedSerialNumbers, iSerialNumber.(string))
	}

	data := map[string]interface{}{
		"ttl":                                d.Get("ttl"),
		"max_ttl":                            d.Get("max_ttl"),
		"allow_localhost":                    d.Get("allow_localhost"),
		"allow_bare_domains":                 d.Get("allow_bare_domains"),
		"allow_subdomains":                   d.Get("allow_subdomains"),
		"allowed_domains_template":           d.Get("allowed_domains_template"),
		"allow_glob_domains":                 d.Get("allow_glob_domains"),
		"allow_any_name":                     d.Get("allow_any_name"),
		"allow_wildcard_certificates":        d.Get("allow_wildcard_certificates"),
		"enforce_hostnames":                  d.Get("enforce_hostnames"),
		"allow_ip_sans":                      d.Get("allow_ip_sans"),
		"allowed_uri_sans":                   d.Get("allowed_uri_sans"),
		"allowed_other_sans":                 d.Get("allowed_other_sans"),
		"server_flag":                        d.Get("server_flag"),
		"client_flag":                        d.Get("client_flag"),
		"code_signing_flag":                  d.Get("code_signing_flag"),
		"email_protection_flag":              d.Get("email_protection_flag"),
		"key_type":                           d.Get("key_type"),
		"key_bits":                           d.Get("key_bits"),
		"use_csr_common_name":                d.Get("use_csr_common_name"),
		"use_csr_sans":                       d.Get("use_csr_sans"),
		"ou":                                 d.Get("ou"),
		"organization":                       d.Get("organization"),
		"country":                            d.Get("country"),
		"locality":                           d.Get("locality"),
		"province":                           d.Get("province"),
		"street_address":                     d.Get("street_address"),
		"postal_code":                        d.Get("postal_code"),
		"generate_lease":                     d.Get("generate_lease"),
		"no_store":                           d.Get("no_store"),
		"require_cn":                         d.Get("require_cn"),
		"basic_constraints_valid_for_non_ca": d.Get("basic_constraints_valid_for_non_ca"),
		"not_before_duration":                d.Get("not_before_duration"),
	}

	if len(allowedDomains) > 0 {
		data["allowed_domains"] = allowedDomains
	}

	if len(keyUsage) > 0 {
		data["key_usage"] = keyUsage
	}

	if len(extKeyUsage) > 0 {
		data["ext_key_usage"] = extKeyUsage
	}

	if policyIdentifiers, ok := d.GetOk("policy_identifiers"); ok {
		data["policy_identifiers"] = policyIdentifiers
	} else if policyIdentifierBlocksRaw, ok := d.GetOk("policy_identifier"); ok {
		data["policy_identifiers"] = pki.ReadPolicyIdentifierBlocks(policyIdentifierBlocksRaw.(*schema.Set))
	}

	if len(allowedSerialNumbers) > 0 {
		data["allowed_serial_numbers"] = allowedSerialNumbers
	}

	log.Printf("[DEBUG] Creating role %s on PKI secret backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating role %s for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created role %s on PKI backend %q", name, backend)

	d.SetId(path)
	return pkiSecretBackendRoleRead(d, meta)
}

func pkiSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	backend, err := pkiSecretBackendRoleBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid role ID %q: %s", path, err)
	}

	name, err := pkiSecretBackendRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading role from %q", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read role from %q", path)
	if secret == nil {
		log.Printf("[WARN] Role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	iAllowedDomains := secret.Data["allowed_domains"].([]interface{})
	allowedDomains := make([]string, 0, len(iAllowedDomains))
	for _, iAllowedDomain := range iAllowedDomains {
		allowedDomains = append(allowedDomains, iAllowedDomain.(string))
	}

	keyBits, err := secret.Data["key_bits"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected key_bits %q to be a number, isn't", secret.Data["key_bits"])
	}

	iKeyUsage := secret.Data["key_usage"].([]interface{})
	keyUsage := make([]string, 0, len(iKeyUsage))
	for _, iUsage := range iKeyUsage {
		keyUsage = append(keyUsage, iUsage.(string))
	}

	iExtKeyUsage := secret.Data["ext_key_usage"].([]interface{})
	extKeyUsage := make([]string, 0, len(iExtKeyUsage))
	for _, iUsage := range iExtKeyUsage {
		extKeyUsage = append(extKeyUsage, iUsage.(string))
	}

	var legacyPolicyIdentifiers []string = nil
	var newPolicyIdentifiers *schema.Set = nil
	if policyIdentifiersRaw, ok := secret.Data["policy_identifiers"]; ok {
		if policyIdentifiersRawList, ok := policyIdentifiersRaw.([]interface{}); ok {
			var err error
			legacyPolicyIdentifiers, newPolicyIdentifiers, err = pki.MakePkiPolicyIdentifiersListOrSet(policyIdentifiersRawList)
			if err != nil {
				return err
			}
		}
	}

	notBeforeDuration := flattenVaultDuration(secret.Data["not_before_duration"])

	iAllowedSerialNumbers := secret.Data["allowed_serial_numbers"].([]interface{})
	allowedSerialNumbers := make([]string, 0, len(iAllowedSerialNumbers))
	for _, iSerialNumber := range iAllowedSerialNumbers {
		allowedSerialNumbers = append(allowedSerialNumbers, iSerialNumber.(string))
	}

	d.Set("backend", backend)
	d.Set("name", name)
	d.Set("ttl", secret.Data["ttl"])
	d.Set("max_ttl", secret.Data["max_ttl"])
	d.Set("allow_localhost", secret.Data["allow_localhost"])
	d.Set("allowed_domains", allowedDomains)
	d.Set("allowed_domains_template", secret.Data["allowed_domains_template"])
	d.Set("allow_bare_domains", secret.Data["allow_bare_domains"])
	d.Set("allow_subdomains", secret.Data["allow_subdomains"])
	d.Set("allow_glob_domains", secret.Data["allow_glob_domains"])
	d.Set("allow_any_name", secret.Data["allow_any_name"])
	d.Set("allow_wildcard_certificates", secret.Data["allow_wildcard_certificates"])
	d.Set("enforce_hostnames", secret.Data["enforce_hostnames"])
	d.Set("allow_ip_sans", secret.Data["allow_ip_sans"])
	d.Set("allowed_uri_sans", secret.Data["allowed_uri_sans"])
	d.Set("allowed_other_sans", secret.Data["allowed_other_sans"])
	d.Set("server_flag", secret.Data["server_flag"])
	d.Set("client_flag", secret.Data["client_flag"])
	d.Set("code_signing_flag", secret.Data["code_signing_flag"])
	d.Set("email_protection_flag", secret.Data["email_protection_flag"])
	d.Set("key_type", secret.Data["key_type"])
	d.Set("key_bits", keyBits)
	d.Set("key_usage", keyUsage)
	d.Set("ext_key_usage", extKeyUsage)
	d.Set("use_csr_common_name", secret.Data["use_csr_common_name"])
	d.Set("use_csr_sans", secret.Data["use_csr_sans"])
	d.Set("ou", secret.Data["ou"])
	d.Set("organization", secret.Data["organization"])
	d.Set("country", secret.Data["country"])
	d.Set("locality", secret.Data["locality"])
	d.Set("province", secret.Data["province"])
	d.Set("street_address", secret.Data["street_address"])
	d.Set("postal_code", secret.Data["postal_code"])
	d.Set("generate_lease", secret.Data["generate_lease"])
	d.Set("no_store", secret.Data["no_store"])
	d.Set("require_cn", secret.Data["require_cn"])
	if len(legacyPolicyIdentifiers) > 0 {
		d.Set("policy_identifiers", legacyPolicyIdentifiers)
	} else {
		d.Set("policy_identifier", newPolicyIdentifiers)
	}
	d.Set("basic_constraints_valid_for_non_ca", secret.Data["basic_constraints_valid_for_non_ca"])
	d.Set("not_before_duration", notBeforeDuration)
	d.Set("allowed_serial_numbers", allowedSerialNumbers)

	return nil
}

func pkiSecretBackendRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Updating PKI secret backend role %q", path)

	iAllowedDomains := d.Get("allowed_domains").([]interface{})
	allowedDomains := make([]string, 0, len(iAllowedDomains))
	for _, iAllowedDomain := range iAllowedDomains {
		allowedDomains = append(allowedDomains, iAllowedDomain.(string))
	}

	iKeyUsage := d.Get("key_usage").([]interface{})
	keyUsage := make([]string, 0, len(iKeyUsage))
	for _, iUsage := range iKeyUsage {
		keyUsage = append(keyUsage, iUsage.(string))
	}

	iExtKeyUsage := d.Get("ext_key_usage").([]interface{})
	extKeyUsage := make([]string, 0, len(iExtKeyUsage))
	for _, iUsage := range iExtKeyUsage {
		extKeyUsage = append(extKeyUsage, iUsage.(string))
	}

	iAllowedSerialNumbers := d.Get("allowed_serial_numbers").([]interface{})
	allowedSerialNumbers := make([]string, 0, len(iAllowedSerialNumbers))
	for _, iSerialNumber := range iAllowedSerialNumbers {
		allowedSerialNumbers = append(allowedSerialNumbers, iSerialNumber.(string))
	}

	data := map[string]interface{}{
		"ttl":                                d.Get("ttl"),
		"max_ttl":                            d.Get("max_ttl"),
		"allow_localhost":                    d.Get("allow_localhost"),
		"allow_bare_domains":                 d.Get("allow_bare_domains"),
		"allowed_domains_template":           d.Get("allowed_domains_template"),
		"allow_subdomains":                   d.Get("allow_subdomains"),
		"allow_glob_domains":                 d.Get("allow_glob_domains"),
		"allow_any_name":                     d.Get("allow_any_name"),
		"enforce_hostnames":                  d.Get("enforce_hostnames"),
		"allow_ip_sans":                      d.Get("allow_ip_sans"),
		"allowed_uri_sans":                   d.Get("allowed_uri_sans"),
		"allowed_other_sans":                 d.Get("allowed_other_sans"),
		"server_flag":                        d.Get("server_flag"),
		"client_flag":                        d.Get("client_flag"),
		"code_signing_flag":                  d.Get("code_signing_flag"),
		"email_protection_flag":              d.Get("email_protection_flag"),
		"key_type":                           d.Get("key_type"),
		"key_bits":                           d.Get("key_bits"),
		"use_csr_common_name":                d.Get("use_csr_common_name"),
		"use_csr_sans":                       d.Get("use_csr_sans"),
		"ou":                                 d.Get("ou"),
		"organization":                       d.Get("organization"),
		"country":                            d.Get("country"),
		"locality":                           d.Get("locality"),
		"province":                           d.Get("province"),
		"street_address":                     d.Get("street_address"),
		"postal_code":                        d.Get("postal_code"),
		"generate_lease":                     d.Get("generate_lease"),
		"no_store":                           d.Get("no_store"),
		"require_cn":                         d.Get("require_cn"),
		"basic_constraints_valid_for_non_ca": d.Get("basic_constraints_valid_for_non_ca"),
		"not_before_duration":                d.Get("not_before_duration"),
	}

	if len(allowedDomains) > 0 {
		data["allowed_domains"] = allowedDomains
	}

	if provider.IsAPISupported(meta, provider.VaultVersion110) {
		data["allow_wildcard_certificates"] = d.Get("allow_wildcard_certificates")
	}

	if len(keyUsage) > 0 {
		data["key_usage"] = keyUsage
	}

	if len(extKeyUsage) > 0 {
		data["ext_key_usage"] = extKeyUsage
	}

	if policyIdentifiers, ok := d.GetOk("policy_identifiers"); ok {
		data["policy_identifiers"] = policyIdentifiers
	} else if policyIdentifierBlocksRaw, ok := d.GetOk("policy_identifier"); ok {
		data["policy_identifiers"] = pki.ReadPolicyIdentifierBlocks(policyIdentifierBlocksRaw.(*schema.Set))
	}

	if len(allowedSerialNumbers) > 0 {
		data["allowed_serial_numbers"] = allowedSerialNumbers
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating PKI secret backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated PKI secret backend role %q", path)

	return pkiSecretBackendRoleRead(d, meta)
}

func pkiSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
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

func pkiSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if role %q exists", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if role %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if role %q exists", path)
	return secret != nil, nil
}

func pkiSecretBackendRolePath(backend string, name string) string {
	return strings.Trim(backend, "/") + "/roles/" + strings.Trim(name, "/")
}

func pkiSecretBackendRoleNameFromPath(path string) (string, error) {
	if !pkiSecretBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := pkiSecretBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func pkiSecretBackendRoleBackendFromPath(path string) (string, error) {
	if !pkiSecretBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := pkiSecretBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
