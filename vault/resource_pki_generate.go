package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"

	"github.com/hashicorp/vault/api"
)

func pkiGenerateResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiGenerateResourceWrite,
		Delete: pkiGenerateResourceDelete,
		Read:   pkiGenerateResourceRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"type": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"root", "intermediate"}, false),
				Description:  "Type of the CA, 'root' or 'intermediate'.",
			},
			"common_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Specifies the requested CN for the certificate.",
			},
			"alt_names": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the requested Subject Alternative Names.",
			},
			"ip_sans": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the requested IP Subject Alternative Names.",
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Specifies the requested Time To Live (after which the certificate will be expired).",
			},
			"key_type": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Default:      "rsa",
				ValidateFunc: validation.StringInSlice([]string{"rsa", "ec"}, false),
				Description:  "Specifies the type of key to generate for generated private keys. Currently, rsa and ec are supported.",
			},
			"key_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Default:     2048,
				Description: "Specifies the number of bits to use for the generated keys.",
			},
			"exclude_cn_from_sans": {
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Default:     false,
				Description: "If true, the given common_name will not be included in DNS or Email Subject Alternate Names (as appropriate).",
			},
			"secret_path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Path to write private key and cert as generic secret. Key material will _not_ be stored in state. Defaults to internal generation.",
			},
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the backend to generate certs for.",
				ForceNew:    true,
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func pkiGenerateResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	log.Printf("common name is %s", d.Get("common_name").(string))
	data := map[string]interface{}{
		"common_name": d.Get("common_name").(string),
	}

	rawAltNames := d.Get("alt_names").([]interface{})
	altNames := make([]string, 0, len(rawAltNames))
	for _, rawAltName := range rawAltNames {
		altNames = append(altNames, rawAltName.(string))
	}
	if len(altNames) > 0 {
		data["alt_names"] = altNames
	}

	rawIpSans := d.Get("ip_sans").([]interface{})
	ipSans := make([]string, 0, len(rawIpSans))
	for _, rawIpSan := range rawIpSans {
		ipSans = append(ipSans, rawIpSan.(string))
	}
	if len(ipSans) > 0 {
		data["ip_sans"] = ipSans
	}

	data["ttl"] = d.Get("ttl").(string)
	data["key_type"] = d.Get("key_type").(string)
	data["key_bits"] = d.Get("key_bits").(int)
	data["exclude_cn_from_sans"] = d.Get("exclude_cn_from_sans").(bool)

	secretType := "internal"
	secretPath := d.Get("secret_path").(string)
	if secretPath != "" {
		secretType = "exported"
	}

	path := fmt.Sprintf("%s/%s/generate/%s", d.Get("backend").(string), d.Get("type").(string), secretType)

	log.Printf("[DEBUG] Generating Vault pki cert at %s", path)
	secret, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	if secretPath != "" {
		log.Printf("[DEBUG] Writing Vault pki values as secret at %s", secretPath)
		if _, err := client.Logical().Write(secretPath, secret.Data); err != nil {
			return fmt.Errorf("error writing to Vault: %s", err)
		}
	}

	d.SetId(path)

	return pkiGenerateResourceRead(d, meta)
}

func pkiGenerateResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	delPath := fmt.Sprintf("%s/root", d.Get("backend").(string))

	log.Printf("[DEBUG] Deleting Vault generated certificate from %q", delPath)
	_, err := client.Logical().Delete(delPath)
	if err != nil {
		return fmt.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}

func pkiGenerateResourceRead(d *schema.ResourceData, meta interface{}) error {
	path := d.Id()

	log.Printf("[DEBUG] Vault generated certificate does not support reading: %s", path)
	return nil
}
