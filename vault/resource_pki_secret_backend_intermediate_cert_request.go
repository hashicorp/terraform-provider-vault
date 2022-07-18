package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
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
				Description:  "Type of intermediate to create. Must be either \"exported\", \"internal\", \"existing\" or \"kms\".",
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"exported", "internal", "existing", "kms"}, false),
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
				ValidateFunc: validation.StringInSlice([]string{"rsa", "ec", "ed25519"}, false),
				// Suppress the diff if group type is "existing" or "kms" because we cannot manage the key type.
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					if d.Get("type").(string) == "existing" || d.Get("type").(string) == "kms" {
						return true
					}
					return false
				},
			},
			"key_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The number of bits to use.",
				ForceNew:    true,
				Default:     2048,
				// Suppress the diff if group type is "existing" or "kms" because we cannot manage the key bits.
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					if d.Get("type").(string) == "existing" || d.Get("type").(string) == "kms" {
						return true
					}
					return false
				},
			},
			"key_name": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Specifies the name of the key when it is created with this resource.",
				ForceNew:     true,
				ValidateFunc: validation.StringNotInSlice([]string{"default"}, false),
			},
			"key_ref": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the key (either default, by name, or by identifier).",
				ForceNew:    true,
				Default:     "default",
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
			"managed_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The managed key's configured name.",
				ForceNew:    true,
			},
			"managed_key_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The managed key's UUID.",
				ForceNew:    true,
			},
		},
	}
}

func pkiSecretBackendIntermediateCertRequestCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

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
		"key_ref":              d.Get("key_ref").(string),
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

	if v, ok := d.GetOk("key_type"); ok {
		data["key_type"] = v.(string)
	}

	if v, ok := d.GetOk("key_bits"); ok {
		data["key_bits"] = v.(int)
	}

	if v, ok := d.GetOk("key_name"); ok {
		data["key_name"] = v.(string)
	}

	if v, ok := d.GetOk("managed_key_name"); ok {
		data["managed_key_name"] = v.(string)
	}

	if v, ok := d.GetOk("managed_key_id"); ok {
		data["managed_key_id"] = v.(string)
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
	if intermediateType == "existing" {
		return strings.Trim(backend, "/") + "/intermediate/cross-sign"
	}
	return strings.Trim(backend, "/") + "/intermediate/generate/" + strings.Trim(intermediateType, "/")
}
