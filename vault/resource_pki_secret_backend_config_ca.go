package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendConfigCAResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendConfigCACreate,
		Read:   ReadWrapper(pkiSecretBackendConfigCARead),
		Delete: pkiSecretBackendConfigCADelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			"pem_bundle": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The key and certificate PEM bundle.",
				ForceNew:    true,
				Sensitive:   true,
			},
		},
	}
}

func pkiSecretBackendConfigCACreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)

	path := pkiSecretBackendConfigCAPath(backend)

	data := map[string]interface{}{
		"pem_bundle": d.Get("pem_bundle").(string),
	}

	log.Printf("[DEBUG] Creating CA config on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating CA config for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created CA config on PKI secret backend %q", backend)

	d.SetId(backend)
	return pkiSecretBackendConfigCARead(d, meta)
}

func pkiSecretBackendConfigCARead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendConfigCADelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendConfigCAPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/ca"
}
