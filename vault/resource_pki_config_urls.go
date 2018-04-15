package vault

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func pkiConfigURLsResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: pkiConfigURLsWrite,
		Read:   pkiConfigURLsRead,
		Update: pkiConfigURLsWrite,
		Delete: pkiConfigURLsDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of the pki backend to configure.",
				ForceNew:    true,
				Default:     "pki",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"issuing_certificates": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"crl_distribution_points": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ocsp_servers": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func pkiConfigURLsWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)

	_, err := client.Logical().Write(backend+"/config/urls", map[string]interface{}{
		"issuing_certificates":    d.Get("issuing_certificates"),
		"crl_distribution_points": d.Get("crl_distribution_points"),
		"ocsp_servers":            d.Get("ocsp_servers"),
	})
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}
	d.SetId(backend)

	return pkiConfigURLsRead(d, meta)
}
func pkiConfigURLsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Id()

	secret, err := client.Logical().Read(backend + "/config/urls")
	if err != nil {
		return fmt.Errorf("error reading to Vault: %s", err)
	}

	d.Set("issuing_certificates", secret.Data["issuing_certificates"])
	d.Set("crl_distribution_points", secret.Data["crl_distribution_points"])
	d.Set("ocsp_servers", secret.Data["ocsp_servers"])

	return nil
}

func pkiConfigURLsDelete(d *schema.ResourceData, meta interface{}) error {
	// There is nothing to actually delete
	return nil
}
