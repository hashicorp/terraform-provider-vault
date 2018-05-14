package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"

	"github.com/hashicorp/vault/api"
)

func pkiRoleResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: pkiRoleResourceWrite,
		Update: pkiRoleResourceWrite,
		Read:   pkiRoleResourceRead,
		Delete: pkiRoleResourceDelete,
		Exists: pkiRoleResourceExists,

		Schema: map[string]*schema.Schema{
			"role": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"ttl": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"max_ttl": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"allow_localhost": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"allowed_domains": &schema.Schema{
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"allow_bare_domains": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"allow_subdomains": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"allow_glob_domains": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"allow_any_name": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"enforce_hostnames": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"allow_ip_sans": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"server_flag": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"client_flag": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"code_signing_flag": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"email_protection_flag": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"key_type": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"key_bits": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},
			"key_usage": &schema.Schema{
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"use_csr_common_name": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"use_csr_sans": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"ou": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"organization": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"generate_lease": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"no_store": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"backend": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "pki",
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func pkiRoleResourcePath(backend, role string) string {
	return strings.Trim(backend, "/") + "/roles/" + strings.Trim(role, "/")
}

func pkiRoleResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)
	path := pkiRoleResourcePath(backend, role)

	data := map[string]interface{}{}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(string)
	}

	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(string)
	}

	if v, ok := d.GetOkExists("allow_localhost"); ok {
		data["allow_localhost"] = v.(bool)
	}

	if v, ok := d.GetOk("allowed_domains"); ok {
		data["allowed_domains"] = v
	}

	if v, ok := d.GetOkExists("allow_bare_domains"); ok {
		data["allow_bare_domains"] = v.(bool)
	}

	if v, ok := d.GetOkExists("allow_subdomains"); ok {
		data["allow_subdomains"] = v.(bool)
	}

	if v, ok := d.GetOkExists("allow_glob_domains"); ok {
		data["allow_glob_domains"] = v.(bool)
	}

	if v, ok := d.GetOkExists("allow_any_name"); ok {
		data["allow_any_name"] = v.(bool)
	}

	if v, ok := d.GetOkExists("enforce_hostnames"); ok {
		data["enforce_hostnames"] = v.(bool)
	}

	if v, ok := d.GetOkExists("allow_ip_sans"); ok {
		data["allow_ip_sans"] = v.(bool)
	}

	if v, ok := d.GetOkExists("server_flag"); ok {
		data["server_flag"] = v.(bool)
	}

	if v, ok := d.GetOkExists("client_flag"); ok {
		data["client_flag"] = v.(bool)
	}

	if v, ok := d.GetOkExists("code_signing_flag"); ok {
		data["code_signing_flag"] = v.(bool)
	}

	if v, ok := d.GetOkExists("email_protection_flag"); ok {
		data["email_protection_flag"] = v.(bool)
	}

	if v, ok := d.GetOk("key_type"); ok {
		data["key_type"] = v.(string)
	}

	if v, ok := d.GetOk("key_bits"); ok {
		data["key_bits"] = v.(int)
	}

	if v, ok := d.GetOk("key_usage"); ok {
		data["key_usage"] = v
	}

	if v, ok := d.GetOkExists("use_csr_common_name"); ok {
		data["use_csr_common_name"] = v.(bool)
	}

	if v, ok := d.GetOkExists("use_csr_sans"); ok {
		data["use_csr_sans"] = v.(bool)
	}

	if v, ok := d.GetOk("ou"); ok {
		data["ou"] = v.(string)
	}

	if v, ok := d.GetOk("organization"); ok {
		data["organization"] = v.(string)
	}

	if v, ok := d.GetOkExists("generate_lease"); ok {
		data["generate_lease"] = v.(bool)
	}

	if v, ok := d.GetOkExists("no_store"); ok {
		data["no_store"] = v.(bool)
	}

	log.Printf("[DEBUG] Writing PKI role %q to PKI backend", path)
	_, err := client.Logical().Write(path, data)

	d.SetId(path)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error configuring PKI role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote PKI role %q to PKI backend", path)

	return pkiRoleResourceRead(d, meta)
}

func pkiRoleResourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading PKI role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("Error reading PKI role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read PKI role %q", path)

	if resp == nil {
		log.Printf("[WARN] PKI role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	iAllowedDomains := resp.Data["allowed_domains"].([]interface{})
	allowedDomains := make([]string, 0, len(iAllowedDomains))
	for _, iAllowedDomain := range iAllowedDomains {
		allowedDomains = append(allowedDomains, iAllowedDomain.(string))
	}

	iKeyUsage := resp.Data["key_usage"].([]interface{})
	keyUsage := make([]string, 0, len(iKeyUsage))
	for _, iUsage := range iKeyUsage {
		keyUsage = append(keyUsage, iUsage.(string))
	}

	keyBits, err := resp.Data["key_bits"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("Expected key_bits to be a number, isn't (%q)", resp.Data["key_bits"])
	}

	d.Set("ttl", resp.Data["ttl"])
	d.Set("max_ttl", resp.Data["max_ttl"])
	d.Set("allow_localhost", resp.Data["allow_localhost"])
	d.Set("allowed_domains", allowedDomains)
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
	d.Set("key_bits", keyBits)
	d.Set("key_usage", keyUsage)
	d.Set("use_csr_common_name", resp.Data["use_csr_common_name"])
	d.Set("use_csr_sans", resp.Data["use_csr_sans"])
	d.Set("ou", resp.Data["ou"])
	d.Set("organization", resp.Data["organization"])
	d.Set("generate_lease", resp.Data["generate_lease"])
	d.Set("no_store", resp.Data["no_store"])

	return nil

}

func pkiRoleResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting PKI role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting PKI role %q", path)
	}
	log.Printf("[DEBUG] Deleted PKI role %q", path)

	return nil
}

func pkiRoleResourceExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Checking if PKI role %q exists", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("Error checking for existence of PKI role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if PKI role %q exists", path)

	return resp != nil, nil
}
