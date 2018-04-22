package vault

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func pkiRoleResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: pkiConfigRoleWrite,
		Read:   pkiConfigRoleRead,
		Update: pkiConfigRoleWrite,
		Delete: pkiConfigRoleDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of the pki backend.",
				ForceNew:    true,
				Default:     "pki",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Specifies the name of the role to create.",
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the Time To Live value provided as a string duration with time suffix. Hour is the largest suffix.",
			},
			"max_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the maximum Time To Live provided as a string duration with time suffix. Hour is the largest suffix.",
			},
			"allow_localhost": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Specifies if clients can request certificates for localhost as one of the requested common names.",
			},
			"allowed_domains": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the domains of the role. This is used with the allow_bare_domains and allow_subdomains options.",
			},
			"allow_bare_domains": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Specifies if clients can request certificates matching the value of the actual domains themselves.",
			},
			"allow_subdomains": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Specifies if clients can request certificates with CNs that are subdomains of the CNs allowed by the other role options.",
			},
			"allow_glob_domains": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Allows names specified in allowed_domains to contain glob patterns.",
			},
			"allow_any_name": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Specifies if clients can request any CN.",
			},
			"enforce_hostnames": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Specifies if only valid host names are allowed for CNs, DNS SANs, and the host part of email addresses.",
			},
			"allow_ip_sans": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Specifies if clients can request IP Subject Alternative Names.",
			},
			"allow_other_sans": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Defines allowed custom OID/UTF8-string SANs.",
			},
			"server_flag": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Specifies if certificates are flagged for server use.",
			},
			"client_flag": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Specifies if certificates are flagged for client use.",
			},
			"code_signing_flag": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Specifies if certificates are flagged for code signing use.",
			},
			"email_protection_flag": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Specifies if certificates are flagged for email protection use.",
			},
			"key_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "rsa",
				Description: "Specifies the type of key to generate for generated private keys.",
			},
			"key_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     2048,
				Description: "Specifies the number of bits to use for the generated keys.",
			},
			"key_usage": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the allowed key usage constraint on issued certificates.",
			},
			"use_csr_common_name": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "When used with the CSR signing endpoint, the common name in the CSR will be used instead of taken from the JSON data.",
			},
			"use_csr_sans": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "When used with the CSR signing endpoint, the subject alternate names in the CSR will be used instead of taken from the JSON data.",
			},
			"ou": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the OU (OrganizationalUnit) values in the subject field of issued certificates.",
			},
			"organization": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the O (Organization) values in the subject field of issued certificates.",
			},
			"country": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the C (Country) values in the subject field of issued certificates.",
			},
			"locality": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the L (Locality) values in the subject field of issued certificates.",
			},
			"province": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the ST (Province) values in the subject field of issued certificates.",
			},
			"street_address": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the Street Address values in the subject field of issued certificates.",
			},
			"postal_code": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the Postal Code values in the subject field of issued certificates.",
			},
			"generate_lease": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Specifies if certificates issued/signed against this role will have Vault leases attached to them.",
			},
			"no_store": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If set, certificates issued/signed against this role will not be stored in the storage backend.",
			},
			"require_cn": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "If set to false, makes the common_name field optional while generating a certificate.",
			},
			"policy_identifiers": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "A comma-separated string or list of policy oids.",
			},
			"basic_constraints_valid_for_non_ca": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Mark Basic Constraints valid when issuing non-CA certificates.",
			},
		},
	}
}

func pkiConfigRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	secretData := map[string]interface{}{
		"allow_localhost":                    d.Get("allow_localhost"),
		"allowed_domains":                    d.Get("allowed_domains"),
		"allow_bare_domains":                 d.Get("allow_bare_domains"),
		"allow_subdomains":                   d.Get("allow_subdomains"),
		"allow_glob_domains":                 d.Get("allow_glob_domains"),
		"allow_any_name":                     d.Get("allow_any_name"),
		"enforce_hostnames":                  d.Get("enforce_hostnames"),
		"allow_ip_sans":                      d.Get("allow_ip_sans"),
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
		"policy_identifiers":                 d.Get("policy_identifiers"),
		"basic_constraints_valid_for_non_ca": d.Get("basic_constraints_valid_for_non_ca"),
	}

	value, ok := d.GetOk("ttl")
	if ok {
		secretData["ttl"] = value
	}
	value, ok = d.GetOk("max_ttl")
	if ok {
		secretData["max_ttl"] = value
	}
	value, ok = d.GetOk("key_usage")
	if ok {
		secretData["key_usage"] = value
	}

	_, err := client.Logical().Write(backend+"/roles/"+name, secretData)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}
	d.SetId(backend + "/roles/" + name)

	return pkiConfigRoleRead(d, meta)
}

func pkiConfigRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		d.SetId("")
		return nil
	}

	for k, v := range secret.Data {
		d.Set(k, v)
	}

	return nil
}

func pkiConfigRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	_, err := client.Logical().Delete(d.Id())
	if err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}
