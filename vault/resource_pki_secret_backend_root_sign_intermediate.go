// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/pem"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendRootSignIntermediateResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendRootSignIntermediateCreate,
		Read:   ReadWrapper(pkiSecretBackendRootSignIntermediateRead),
		Update: pkiSecretBackendRootSignIntermediateUpdate,
		Delete: pkiSecretBackendCertDelete,
		StateUpgraders: []schema.StateUpgrader{
			{
				Version: 0,
				Type:    pkiSecretRootSignIntermediateRV0().CoreConfigSchema().ImpliedType(),
				Upgrade: pkiSecretRootSignIntermediateRUpgradeV0,
			},
			{
				Version: 1,
				Type:    pkiSecretSerialNumberResourceV0().CoreConfigSchema().ImpliedType(),
				Upgrade: pkiSecretSerialNumberUpgradeV0,
			},
		},
		SchemaVersion: 2,
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
				Description: "List of alternative URIs.",
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
				Description: "The signed intermediate CA certificate.",
			},
			"issuing_ca": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The issuing CA certificate.",
			},
			"ca_chain": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The CA chain as a list of format specific certificates",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"certificate_bundle": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The concatenation of the intermediate and issuing CA certificates (PEM encoded). " +
					"Requires the format to be set to any of: pem, " +
					"pem_bundle. The value will be empty for all other formats.",
			},
			"serial": {
				Type:        schema.TypeString,
				Computed:    true,
				Deprecated:  "Use serial_number instead",
				Description: "The serial number.",
			},
			"serial_number": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certificate's serial number, hex formatted.",
			},
			"revoke": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Revoke the certificate upon resource destruction.",
			},
		},
	}
}

func pkiSecretBackendRootSignIntermediateCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

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
	d.Set("serial", resp.Data["serial_number"])
	d.Set("serial_number", resp.Data["serial_number"])

	if err := setCAChain(d, resp); err != nil {
		return err
	}

	if err := setCertificateBundle(d, resp); err != nil {
		return err
	}

	d.SetId(fmt.Sprintf("%s/%s", backend, commonName))

	return pkiSecretBackendRootSignIntermediateRead(d, meta)
}

func setCAChain(d *schema.ResourceData, resp *api.Secret) error {
	field := "ca_chain"
	var caChain []string
	if v, ok := resp.Data[field]; ok && v != nil {
		switch v := v.(type) {
		case []interface{}:
			for _, v := range v {
				caChain = append(caChain, v.(string))
			}
		default:
			return fmt.Errorf("response contains an unexpected type %T for %q", v, field)
		}
	}

	// provide the CAChain from the issuing_ca and the intermediate CA certificate
	var err error
	if len(caChain) == 0 {
		caChain, err = getCAChain(resp.Data, !isPEMFormat(d))
		if err != nil {
			return err
		}
	}

	return d.Set(field, caChain)
}

func getCAChain(m map[string]interface{}, literal bool) ([]string, error) {
	return parseCertChain(m, true, literal)
}

func isPEMFormat(d *schema.ResourceData) bool {
	format := d.Get("format").(string)
	switch format {
	case "pem", "pem_bundle":
		return true
	default:
		return false
	}
}

func setCertificateBundle(d *schema.ResourceData, resp *api.Secret) error {
	field := "certificate_bundle"
	if !isPEMFormat(d) {
		log.Printf("[WARN] Cannot set the %q, not in PEM format", field)
		return nil
	}

	chain, err := parseCertChain(resp.Data, false, false)
	if err != nil {
		return err
	}

	return d.Set(field, strings.Join(chain, "\n"))
}

func parseCertChain(m map[string]interface{}, asCA, literal bool) ([]string, error) {
	var chain []string
	seen := make(map[string]bool)
	parseCert := func(data string) error {
		var b *pem.Block
		rest := []byte(data)
		for {
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}

			cert := strings.Trim(string(pem.EncodeToMemory(b)), "\n")
			if _, ok := seen[cert]; !ok {
				chain = append(chain, cert)
				seen[cert] = true
			}
		}

		return nil
	}

	fields := []string{"issuing_ca", "certificate"}
	if !asCA {
		fields = []string{fields[1], fields[0]}
	}

	for _, k := range fields {
		if v, ok := m[k]; ok && v.(string) != "" {
			value := v.(string)
			if literal {
				chain = append(chain, value)
			} else if err := parseCert(value); err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("required certificate for %q is missing or empty", k)
		}
	}

	return chain, nil
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

func pkiSecretRootSignIntermediateRV0() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"ca_chain": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func pkiSecretRootSignIntermediateRUpgradeV0(
	_ context.Context, rawState map[string]interface{}, _ interface{},
) (map[string]interface{}, error) {
	caChain, err := getCAChain(rawState, false)
	if err != nil {
		return nil, err
	}
	rawState["ca_chain"] = caChain

	return rawState, nil
}
