package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"
	"log"
	"strings"
)

func pkiSecretBackendIntermediateCertRequestResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendIntermediateCertRequestCreate,
		Read:   pkiSecretBackendIntermediateCertRequestRead,
		Delete: pkiSecretBackendIntermediateCertRequestDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			"type": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Type of intermediate to create. Must be either \"exported\" or \"internal\".",
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"exported", "internal"}, false),
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
			"key_type": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The desired key type.",
				ForceNew:     true,
				Default:      "rsa",
				ValidateFunc: validation.StringInSlice([]string{"rsa", "ec"}, false),
			},
			"key_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The number of bits to use.",
				ForceNew:    true,
				Default:     2048,
			},
			"exclude_cn_from_sans": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Flag to exclude CN from SANs.",
				ForceNew:    true,
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
			"csr": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The CSR.",
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
		},
	}
}

func pkiSecretBackendIntermediateCertRequestCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	intermediateType := d.Get("type").(string)

	path := pkiSecretBackendIntermediateGeneratePath(backend, intermediateType)

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

	iURISans := d.Get("uri_sans").([]interface{})
	uriSans := make([]string, 0, len(iURISans))
	for _, iUriSan := range iURISans {
		uriSans = append(uriSans, iUriSan.(string))
	}

	iOtherSans := d.Get("other_sans").([]interface{})
	otherSans := make([]string, 0, len(iOtherSans))
	for _, iOtherSan := range iOtherSans {
		otherSans = append(otherSans, iOtherSan.(string))
	}

	data := map[string]interface{}{
		"common_name":          d.Get("common_name").(string),
		"format":               d.Get("format").(string),
		"private_key_format":   d.Get("private_key_format").(string),
		"key_type":             d.Get("key_type").(string),
		"key_bits":             d.Get("key_bits").(int),
		"exclude_cn_from_sans": d.Get("exclude_cn_from_sans").(bool),
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

	log.Printf("[DEBUG] Creating intermediate cert request on PKI secret backend %q", backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating intermediate cert request for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created intermediate cert request on PKI secret backend %q", backend)

	d.Set("csr", resp.Data["csr"])

	if d.Get("type") == "exported" {
		d.Set("private_key", resp.Data["private_key"])
		d.Set("private_key_type", resp.Data["private_key_type"])
	}

	d.SetId(path)
	return pkiSecretBackendIntermediateCertRequestRead(d, meta)
}

func pkiSecretBackendIntermediateCertRequestRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendIntermediateCertRequestDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendIntermediateGeneratePath(backend string, intermediateType string) string {
	return strings.Trim(backend, "/") + "/intermediate/generate/" + strings.Trim(intermediateType, "/")
}
