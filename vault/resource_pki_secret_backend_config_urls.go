package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func pkiSecretBackendConfigUrlsResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendConfigUrlsCreate,
		Read:   pkiSecretBackendConfigUrlsRead,
		Update: pkiSecretBackendConfigUrlsUpdate,
		Delete: pkiSecretBackendConfigUrlsDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Optional:    false,
				ForceNew:    false,
				Description: "The path of the PKI secret backend the resource belongs to.",
			},
			"issuing_certificates": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Specifies the URL values for the Issuing Certificate field. This can be a comma-separated string list.",
				ForceNew:    false,
			},
			"crl_distribution_points": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Specifies the URL values for the CRL Distribution Points field. This can be a comma-separated string list.",
				ForceNew:    false,
			},
			"ocsp_servers": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Specifies the URL values for the OCSP Servers field. This can be a comma-separated string list.",
				ForceNew:    false,
			},
		},
	}
}

func pkiSecretBackendConfigUrlsCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)

	path := pkiSecretBackendConfigUrlsPath(backend)

	issuingCertificates := d.Get("issuing_certificates").(string)
	crlDistributionsPoints := d.Get("crl_distribution_points").(string)
	ocspServers := d.Get("ocsp_servers").(string)

	data := map[string]interface{}{
		"issuing_certificates":    issuingCertificates,
		"crl_distribution_points": crlDistributionsPoints,
		"ocsp_servers":            ocspServers,
	}

	log.Printf("[DEBUG] Creating URL config on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating URL config PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created URL config on PKI secret backend %q", backend)

	d.SetId(fmt.Sprintf("%s/config/urls", backend))
	return pkiSecretBackendConfigUrlsRead(d, meta)
}

func pkiSecretBackendConfigUrlsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	backend := pkiSecretBackendConfigUrlsPath(path)

	log.Printf("[DEBUG] Reading URL config from PKI secret backend %q", backend)
	config, err := client.Logical().Read(path)

	if err != nil {
		log.Printf("[WARN] Removing path %q its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid path ID %q: %s", path, err)
	}

	d.Set("issuing_certificates", config.Data["issuing_certificates"])
	d.Set("crl_distribution_points", config.Data["crl_distribution_points"])
	d.Set("ocsp_servers", config.Data["ocsp_servers"])

	return nil
}

func pkiSecretBackendConfigUrlsUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Id()

	path := pkiSecretBackendConfigUrlsPath(backend)

	issuingCertificates := d.Get("issuing_certificates").(string)
	crlDistributionsPoints := d.Get("crl_distribution_points").(string)
	ocspServers := d.Get("ocsp_servers").(string)

	data := map[string]interface{}{
		"issuing_certificates":    issuingCertificates,
		"crl_distribution_points": crlDistributionsPoints,
		"ocsp_servers":            ocspServers,
	}

	log.Printf("[DEBUG] Updating URL config on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating URL config for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Updated URL config on PKI secret backend %q", backend)

	return pkiSecretBackendConfigUrlsRead(d, meta)

}

func pkiSecretBackendConfigUrlsDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendConfigUrlsPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/urls"
}
