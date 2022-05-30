package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func sshSecretBackendCAResource() *schema.Resource {
	return &schema.Resource{
		Create: sshSecretBackendCACreate,
		Read:   sshSecretBackendCARead,
		Delete: sshSecretBackendCADelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "ssh",
				ForceNew:    true,
				Description: "The path of the SSH Secret Backend where the CA should be configured",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"generate_signing_key": {
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Description: "Whether Vault should generate the signing key pair internally.",
			},
			"private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Sensitive:   true,
				Computed:    true,
				Description: "Private key part the SSH CA key pair; required if generate_signing_key is false.",
			},
			"public_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "Public key part the SSH CA key pair; required if generate_signing_key is false.",
			},
		},
	}
}

func sshSecretBackendCACreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	backend := d.Get("backend").(string)

	data := make(map[string]interface{})
	if generateSigningKey, ok := d.Get("generate_signing_key").(bool); ok {
		data["generate_signing_key"] = generateSigningKey
	}
	if privateKey, ok := d.Get("private_key").(string); ok {
		data["private_key"] = privateKey
	}
	if publicKey, ok := d.Get("public_key").(string); ok {
		data["public_key"] = publicKey
	}

	log.Printf("[DEBUG] Writing CA information on SSH backend %q", backend)
	_, err := client.Logical().Write(backend+"/config/ca", data)
	if err != nil {
		return fmt.Errorf("Error writing CA information for backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Written CA information on SSH backend %q", backend)

	d.SetId(backend)
	return sshSecretBackendCARead(d, meta)
}

func sshSecretBackendCARead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Id()

	log.Printf("[DEBUG] Reading CA information from SSH backend %q", backend)
	secret, err := client.Logical().Read(backend + "/config/ca")
	if err != nil {
		if apiRespErr, ok := err.(*api.ResponseError); ok {
			for _, e := range apiRespErr.Errors {
				if e == "keys haven't been configured yet" {
					log.Printf("[WARN] CA information not found in SSH backend %q, removing from state", backend)
					d.SetId("")
					return nil
				}
			}
		}
		return fmt.Errorf("Error reading CA information from SSH backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Read CA information from SSH backend %q", backend)
	if secret == nil {
		log.Printf("[WARN] CA information not found in SSH backend %q, removing from state", backend)
		d.SetId("")
		return nil
	}
	d.Set("public_key", secret.Data["public_key"])
	d.Set("backend", backend)

	// the API doesn't return private_key and generate_signing_key
	// So... if they drift, they drift.

	return nil
}

func sshSecretBackendCADelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Id()
	log.Printf("[DEBUG] Deleting CA configuration for SSH backend %q", backend)
	_, err := client.Logical().Delete(backend + "/config/ca")
	if err != nil {
		return fmt.Errorf("Error deleting CA configuration for SSH backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Deleted CA configuration for SSH backend %q", backend)

	return nil
}
