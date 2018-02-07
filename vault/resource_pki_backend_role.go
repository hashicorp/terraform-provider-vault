package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	pkiBackendRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/roles/.+$")
	pkiBackendRoleNameFromPathRegex    = regexp.MustCompile("^.+/roles/(.+)$")
)

func pkiBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiBackendRoleWrite,
		Read:   pkiBackendRoleRead,
		Update: pkiBackendRoleWrite,
		Delete: pkiBackendRoleDelete,
		Exists: pkiBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role.",
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The TTL period of certificates issued using this role, provided as a duration.",
			},
			"max_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The maximum TTL of certificates issued using this role, provided as a duration.",
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
				Description: "Policies to be set on tokens issued using this role.",
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
				Description: "Specifies the type of key to generate for generated private keys. Currently, rsa and ec are supported.",
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
				Description: "Policies to be set on tokens issued using this role.",
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
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the OU (OrganizationalUnit) values in the subject field of issued certificates.",
			},
			"organization": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the O (Organization) values in the subject field of issued certificates.",
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
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the PKI backend to configure.",
				ForceNew:    true,
				Default:     "pki",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func pkiBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := pkiBackendRolePath(backend, role)

	log.Printf("[DEBUG] Writing PKI backend role %q", path)

	data := map[string]interface{}{}

	data["ttl"] = d.Get("ttl").(string)
	data["max_ttl"] = d.Get("max_ttl").(string)
	data["allow_localhost"] = d.Get("allow_localhost").(bool)

	iDomains := d.Get("allowed_domains").([]interface{})
	domains := make([]string, 0, len(iDomains))
	for _, iDomain := range iDomains {
		domains = append(domains, iDomain.(string))
	}
	if len(domains) > 0 {
		data["allowed_domains"] = domains
	}

	data["allow_bare_domains"] = d.Get("allow_bare_domains").(bool)
	data["allow_subdomains"] = d.Get("allow_subdomains").(bool)
	data["allow_glob_domains"] = d.Get("allow_glob_domains").(bool)
	data["allow_any_name"] = d.Get("allow_any_name").(bool)
	data["enforce_hostnames"] = d.Get("enforce_hostnames").(bool)
	data["allow_ip_sans"] = d.Get("allow_ip_sans").(bool)
	data["client_flag"] = d.Get("client_flag").(bool)
	data["code_signing_flag"] = d.Get("code_signing_flag").(bool)
	data["email_protection_flag"] = d.Get("email_protection_flag").(bool)
	data["key_type"] = d.Get("key_type").(string)
	data["key_bits"] = d.Get("key_bits").(int)

	iUsages := d.Get("key_usage").([]interface{})
	usages := make([]string, 0, len(iUsages))
	for _, iUsage := range iUsages {
		usages = append(usages, iUsage.(string))
	}
	if len(usages) > 0 {
		data["key_usage"] = usages
	}

	data["use_csr_common_name"] = d.Get("use_csr_common_name").(bool)
	data["use_csr_sans"] = d.Get("use_csr_sans").(bool)
	data["ou"] = d.Get("ou").(string)
	data["organization"] = d.Get("organization").(string)
	data["generate_lease"] = d.Get("generate_lease").(bool)
	data["no_store"] = d.Get("no_store").(bool)

	_, err := client.Logical().Write(path, data)

	d.SetId(path)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error writing PKI backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote PKI backend role %q", path)

	return pkiBackendRoleRead(d, meta)
}

func pkiBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	backend, err := pkiBackendRoleBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("Invalid path %q for PKI backend role: %s", path, err)
	}

	role, err := pkiBackendRoleNameFromPath(path)
	if err != nil {
		return fmt.Errorf("Invalid path %q for PKI backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading PKI backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("Error reading PKI backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read PKI backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] PKI backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	iDomains := resp.Data["allowed_domains"].([]interface{})
	domains := make([]string, 0, len(iDomains))
	for _, iDomain := range iDomains {
		domains = append(domains, iDomain.(string))
	}

	iUsages := resp.Data["key_usage"].([]interface{})
	usages := make([]string, 0, len(iUsages))
	for _, iUsage := range iUsages {
		usages = append(usages, iUsage.(string))
	}

	d.Set("backend", backend)
	d.Set("role", role)
	d.Set("ttl", resp.Data["ttl"])
	d.Set("max_ttl", resp.Data["max_ttl"])
	d.Set("allow_localhost", resp.Data["allow_localhost"])
	d.Set("allowed_domains", domains)
	d.Set("allow_bare_domains", resp.Data["allow_bare_domains"])
	d.Set("allow_subdomains", resp.Data["allow_subdomains"])
	d.Set("allow_glob_domains", resp.Data["allow_glob_domains"])
	d.Set("allow_any_name", resp.Data["allow_any_name"])
	d.Set("enforce_hostnames", resp.Data["enforce_hostnames"])
	d.Set("allow_ip_sans", resp.Data["allow_ip_sans"])
	d.Set("server_flag", resp.Data["server_flag"])
	d.Set("client_flag", resp.Data["client_flag"])
	d.Set("code_signing_flag", resp.Data["code_signing_flag"])
	d.Set("email_protection_flag", resp.Data["email_protection_flag"])
	d.Set("key_type", resp.Data["key_type"])
	d.Set("key_bits", resp.Data["key_bits"])
	d.Set("key_usage", usages)
	d.Set("use_csr_common_name", resp.Data["use_csr_common_name"])
	d.Set("use_csr_sans", resp.Data["use_csr_sans"])
	d.Set("ou", resp.Data["ou"])
	d.Set("organization", resp.Data["organization"])
	d.Set("generate_lease", resp.Data["generate_lease"])
	d.Set("no_store", resp.Data["no_store"])

	return nil
}

func pkiBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting PKI backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting PKI backend role %q", path)
	}
	log.Printf("[DEBUG] Deleted PKI backend role %q", path)

	return nil
}

func pkiBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if PKI backend role %q exists", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("Error checking if PKI backend role %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if PKI backend role %q exists", path)

	return resp != nil, nil
}

func pkiBackendRolePath(backend, role string) string {
	return strings.Trim(backend, "/") + "/roles/" + strings.Trim(role, "/")
}

func pkiBackendRoleNameFromPath(path string) (string, error) {
	if !pkiBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := pkiBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func pkiBackendRoleBackendFromPath(path string) (string, error) {
	if !pkiBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := pkiBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
