package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	"github.com/hashicorp/vault/api"
)

func pkiSecretBackendCertResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendCertCreate,
		Read:   pkiSecretBackendCertRead,
		Update: pkiSecretBackendCertUpdate,
		Delete: pkiSecretBackendCertDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role to create the certificate against.",
				ForceNew:    true,
			},
			"common_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "CN of the certificate to create.",
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
				Type:        schema.TypeInt,
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
			"private_key_format": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The private key format.",
				ForceNew:     true,
				Default:      "der",
				ValidateFunc: validation.StringInSlice([]string{"der", "pkcs8"}, false),
			},
			"exclude_cn_from_sans": {
				Type:        schema.TypeBool,
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
			"private_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The private key.",
				Sensitive:   true,
			},
			"private_key_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The private key type.",
			},
			"serial_number": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The serial number.",
			},
		},
	}
}

func pkiSecretBackendCertCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := pkiSecretBackendCertPath(backend, name)

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

	iOtherSans := d.Get("other_sans").([]interface{})
	otherSans := make([]string, 0, len(iOtherSans))
	for _, iOtherSan := range iOtherSans {
		otherSans = append(otherSans, iOtherSan.(string))
	}

	data := map[string]interface{}{
		"common_name":          d.Get("common_name").(string),
		"ttl":                  d.Get("ttl").(int),
		"format":               d.Get("format").(string),
		"private_key_format":   d.Get("private_key_format").(string),
		"exclude_cn_from_sans": d.Get("exclude_cn_from_sans").(bool),
	}

	if len(altNames) > 0 {
		data["alt_names"] = strings.Join(altNames, ",")
	}

	if len(ipSans) > 0 {
		data["ip_sans"] = strings.Join(ipSans, ",")
	}

	if len(otherSans) > 0 {
		data["other_sans"] = strings.Join(otherSans, ",")
	}

	log.Printf("[DEBUG] Creating certificate %s by %s on PKI secret backend %q", commonName, name, backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating certificate %s by %s for PKI secret backend %q: %s", commonName, name,
			backend, err)
	}
	log.Printf("[DEBUG] Created certificate %s by %s on PKI secret backend %q", commonName, name, backend)

	d.Set("certificate", resp.Data["certificate"])
	d.Set("issuing_ca", resp.Data["issuing_ca"])
	d.Set("ca_chain", strings.Join(convertIntoSliceOfString(resp.Data["ca_chain"])[:], "\n"))
	d.Set("private_key", resp.Data["private_key"])
	d.Set("private_key_type", resp.Data["private_key_type"])
	d.Set("serial_number", resp.Data["serial_number"])

	d.SetId(fmt.Sprintf("%s/%s/%s", backend, name, commonName))
	return pkiSecretBackendCertRead(d, meta)
}

func pkiSecretBackendCertRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendCertUpdate(d *schema.ResourceData, m interface{}) error {
	return nil
}

func pkiSecretBackendCertDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendCertPath(backend string, name string) string {
	return strings.Trim(backend, "/") + "/issue/" + strings.Trim(name, "/")
}

func convertIntoSliceOfString(slice interface{}) []string {
	intSlice := slice.([]interface{})
	strSlice := make([]string, len(intSlice))
	for i, v := range intSlice {
		strSlice[i] = v.(string)
	}
	return strSlice
}
