package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func pkiSecretBackendCrlConfigResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendCrlConfigCreate,
		Read:   pkiSecretBackendCrlConfigRead,
		Update: pkiSecretBackendCrlConfigUpdate,
		Delete: pkiSecretBackendCrlConfigDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path of the PKI secret backend the resource belongs to.",
				ForceNew:    true,
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"expiry": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the time until expiration.",
			},
			"disable": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Disables or enables CRL building",
			},
		},
	}
}

func pkiSecretBackendCrlConfigCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	path := pkiSecretBackendCrlConfigPath(backend)

	data := make(map[string]interface{})
	if expiry, ok := d.GetOk("expiry"); ok {
		data["expiry"] = expiry
	}
	if disable, ok := d.GetOk("disable"); ok {
		data["disable"] = disable
	}

	log.Printf("[DEBUG] Creating CRL config on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating CRL config PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created CRL config on PKI secret backend %q", backend)

	d.SetId(path)
	return pkiSecretBackendCrlConfigRead(d, meta)
}

func pkiSecretBackendCrlConfigRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	backend := pkiSecretBackendCrlConfigPath(path)

	log.Printf("[DEBUG] Reading CRL config from PKI secret backend %q", backend)
	config, err := client.Logical().Read(path)

	if err != nil {
		log.Printf("[WARN] Removing path %q its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid path ID %q: %s", path, err)
	}

	d.Set("expiry", config.Data["expiry"])
	d.Set("disable", config.Data["disable"])

	return nil
}

func pkiSecretBackendCrlConfigUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	backend := pkiSecretBackendCrlConfigPath(path)

	data := make(map[string]interface{})
	if expiry, ok := d.GetOk("expiry"); ok {
		data["expiry"] = expiry
	}
	if disable, ok := d.GetOk("disable"); ok {
		data["disable"] = disable
	}

	log.Printf("[DEBUG] Updating CRL config on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating CRL config for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Updated CRL config on PKI secret backend %q", backend)

	return pkiSecretBackendCrlConfigRead(d, meta)

}

func pkiSecretBackendCrlConfigDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendCrlConfigPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/crl"
}
