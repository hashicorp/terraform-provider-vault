package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	"github.com/hashicorp/vault/api"
)

func pkiSecretBackendSignResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendSignCreate,
		Read:   pkiSecretBackendSignRead,
		Update: pkiSecretBackendSignUpdate,
		Delete: pkiSecretBackendSignDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the role belongs to.",
				ForceNew:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role to create the certificate against.",
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
			"other_sans": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of other SANs.",
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
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    false,
				Description: "Time to leave.",
			},
			"format": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The format of data.",
				ForceNew:     true,
				Default:      "pem",
				ValidateFunc: validation.StringInSlice([]string{"pem", "der", "pem_bundle"}, false),
			},
			"exclude_cn_from_sans": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Flag to exclude CN from SANs.",
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
				Description: "The serial.",
			},
		},
	}
}

func pkiSecretBackendSignCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := pkiSecretBackendIssuePath(backend, name)

	commonName := d.Get("commonName").(string)

	iAltNames := d.Get("alt_names").([]interface{})
	altNames := make([]string, 0, len(iAltNames))
	for _, iAltName := range iAltNames {
		altNames = append(altNames, iAltName.(string))
	}

	iOtherSans := d.Get("other_sans").([]interface{})
	otherSans := make([]string, 0, len(iOtherSans))
	for _, iOtherSan := range iOtherSans {
		otherSans = append(otherSans, iOtherSan.(string))
	}

	iIPSans := d.Get("ip_sans").([]interface{})
	ipSans := make([]string, 0, len(iIPSans))
	for _, iIpSan := range iIPSans {
		ipSans = append(ipSans, iIpSan.(string))
	}

	iURISans := d.Get("uri_sans").([]interface{})
	uriSans := make([]string, 0, len(iURISans))
	for _, iUriSan := range iURISans {
		uriSans = append(uriSans, iUriSan.(string))
	}

	data := map[string]interface{}{
		"csr":                  d.Get("csr").(string),
		"commonName":           d.Get("commonName").(string),
		"ttl":                  d.Get("ttl").(string),
		"format":               d.Get("format").(string),
		"exclude_cn_from_sans": d.Get("exclude_cn_from_sans").(string),
	}

	if len(altNames) > 0 {
		data["alt_names"] = altNames
	}

	if len(otherSans) > 0 {
		data["other_sans"] = otherSans
	}

	if len(ipSans) > 0 {
		data["ip_sans"] = ipSans
	}

	if len(uriSans) > 0 {
		data["uri_sans"] = uriSans
	}

	log.Printf("[DEBUG] Creating certificate sign %s by %s on PKI secret backend %q", commonName, name,
		backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating certificate sign %s by %s for PKI secret backend %q: %s",
			commonName, name, backend, err)
	}
	log.Printf("[DEBUG] Created certificate sign %s by %s on PKI secret backend %q", commonName, name,
		backend)

	d.Set("certificate", resp.Data["certificate"])
	d.Set("issuing_ca", resp.Data["issuing_ca"])
	d.Set("ca_chain", resp.Data["ca_chain"])
	d.Set("serial", resp.Data["serial"])

	d.SetId(fmt.Sprintf("%s/%s/%s", backend, name, commonName))
	return pkiSecretBackendSignRead(d, meta)
}

func pkiSecretBackendSignRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendSignUpdate(d *schema.ResourceData, m interface{}) error {
	return nil
}

func pkiSecretBackendSignDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendIssuePath(backend string, name string) string {
	return strings.Trim(backend, "/") + "/sign/" + strings.Trim(name, "/")
}
