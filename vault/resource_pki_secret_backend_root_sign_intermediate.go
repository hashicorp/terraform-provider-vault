package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"
)

func pkiSecretBackendRootSignIntermediateResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendRootSignIntermediateCreate,
		Read:   pkiSecretBackendRootSignIntermediateRead,
		Update: pkiSecretBackendRootSignIntermediateUpdate,
		Delete: pkiSecretBackendRootSignIntermediateDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			"csr": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The CSR.",
				ForceNew:    true,
			},
			"common_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "CN of intermediate to create.",
				ForceNew:    true,
			},
			"alt_names": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of alternative names.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ip_sans": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of alternative IPs.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"uri_sans": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of alterative URIs.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"other_sans": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of other SANs.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    false,
				Description: "Time to live.",
			},
			"format": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The format of data.",
				ForceNew:     true,
				Default:      "pem",
				ValidateFunc: validation.StringInSlice([]string{"pem", "der", "pem_bundle"}, false),
			},
			"max_path_length": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The maximum path length to encode in the generated certificate.",
				ForceNew:    true,
				Default:     -1,
			},
			"exclude_cn_from_sans": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Flag to exclude CN from SANs.",
				ForceNew:    true,
			},
			"use_csr_values": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Preserve CSR values.",
				ForceNew:    true,
				Default:     false,
			},
			"permitted_dns_domains": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of domains for which certificates are allowed to be issued.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ou": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The organization unit.",
				ForceNew:    true,
			},
			"organization": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The organization.",
				ForceNew:    true,
			},
			"country": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The country.",
				ForceNew:    true,
			},
			"locality": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The locality.",
				ForceNew:    true,
			},
			"province": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The province.",
				ForceNew:    true,
			},
			"street_address": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The street address.",
				ForceNew:    true,
			},
			"postal_code": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The postal code.",
				ForceNew:    true,
			},
			"certificate": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certicate.",
			},
			"issuing_ca": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The issuing CA.",
			},
			"ca_chain": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The CA chain.",
			},
			"serial": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The serial number.",
			},
		},
	}
}

func pkiSecretBackendRootSignIntermediateCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)

	path := pkiSecretBackendRootSignIntermediateCreatePath(backend)

	commonName := d.Get("common_name").(string)

	iAltNames := d.Get("alt_names").([]interface{})
	altNames := make([]string, 0, len(iAltNames))
	for _, iAltName := range iAltNames {
		altNames = append(altNames, iAltName.(string))
	}

	iIPSans := d.Get("ip_sans").([]interface{})
	ipSans := make([]string, 0, len(iIPSans))
	for _, iIpSan := range iIPSans {
		ipSans = append(ipSans, iIpSan.(string))
	}

	iUriSans := d.Get("uri_sans").([]interface{})
	uriSans := make([]string, 0, len(iUriSans))
	for _, iUriSan := range iUriSans {
		uriSans = append(uriSans, iUriSan.(string))
	}

	iOtherSans := d.Get("other_sans").([]interface{})
	otherSans := make([]string, 0, len(iOtherSans))
	for _, iOtherSan := range iOtherSans {
		otherSans = append(otherSans, iOtherSan.(string))
	}

	iPermittedDNSDomains := d.Get("permitted_dns_domains").([]interface{})
	permittedDNSDomains := make([]string, 0, len(iPermittedDNSDomains))
	for _, iPermittedDNSDomain := range iPermittedDNSDomains {
		permittedDNSDomains = append(permittedDNSDomains, iPermittedDNSDomain.(string))
	}

	data := map[string]interface{}{
		"csr":                  d.Get("csr").(string),
		"common_name":          d.Get("common_name").(string),
		"ttl":                  d.Get("ttl").(string),
		"format":               d.Get("format").(string),
		"max_path_length":      d.Get("max_path_length").(int),
		"exclude_cn_from_sans": d.Get("exclude_cn_from_sans").(bool),
		"use_csr_values":       d.Get("use_csr_values").(bool),
		"ou":                   d.Get("ou").(string),
		"organization":         d.Get("organization").(string),
		"country":              d.Get("country").(string),
		"locality":             d.Get("locality").(string),
		"province":             d.Get("province").(string),
		"street_address":       d.Get("street_address").(string),
		"postal_code":          d.Get("postal_code").(string),
	}

	if len(altNames) > 0 {
		data["alt_names"] = strings.Join(altNames, ",")
	}

	if len(ipSans) > 0 {
		data["ip_sans"] = strings.Join(ipSans, ",")
	}

	if len(uriSans) > 0 {
		data["uri_sans"] = strings.Join(uriSans, ",")
	}

	if len(otherSans) > 0 {
		data["other_sans"] = strings.Join(otherSans, ",")
	}

	if len(permittedDNSDomains) > 0 {
		data["permitted_dns_domains"] = strings.Join(permittedDNSDomains, ",")
	}

	log.Printf("[DEBUG] Creating root sign-intermediate on PKI secret backend %q", backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating root sign-intermediate on PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created root sign-intermediate on PKI secret backend %q", backend)

	d.Set("certificate", resp.Data["certificate"])
	d.Set("issuing_ca", resp.Data["issuing_ca"])
	d.Set("ca_chain", resp.Data["ca_chain"])
	d.Set("serial", resp.Data["serial_number"])

	d.SetId(fmt.Sprintf("%s/%s", backend, commonName))
	return pkiSecretBackendRootSignIntermediateRead(d, meta)
}

func pkiSecretBackendRootSignIntermediateRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendRootSignIntermediateUpdate(d *schema.ResourceData, m interface{}) error {
	return nil
}

func pkiSecretBackendRootSignIntermediateDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendRootSignIntermediateCreatePath(backend string) string {
	return strings.Trim(backend, "/") + "/root/sign-intermediate"
}
