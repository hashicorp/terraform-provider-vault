package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func pkiConfigCAResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: pkiConfigCAWrite,
		Read:   pkiConfigCARead,
		Update: pkiConfigCAWrite,
		Delete: pkiConfigCaDelete,

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
			"cert": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The pem encoded certificate of the CA.",
			},
			"key": {
				Type:             schema.TypeString,
				Required:         true,
				StateFunc:        pkiPemSha,
				DiffSuppressFunc: pkiKeyDiff,
				Description:      "The pem encoded key of the CA.",
			},
		},
	}
}

func pkiPemSha(pemI interface{}) string {
	pem := pemI.(string)

	h := sha256.New()
	h.Write([]byte(pem))

	return hex.EncodeToString(h.Sum(nil))
}

func pkiKeyDiff(k, old, new string, d *schema.ResourceData) bool {
	h := sha256.New()
	h.Write([]byte(new))
	newSha := hex.EncodeToString(h.Sum(nil))

	return newSha == old
}

func pkiConfigCAWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	cert := d.Get("cert").(string)
	key := d.Get("key").(string)

	_, err := client.Logical().Write(backend+"/config/ca", map[string]interface{}{
		"pem_bundle": fmt.Sprintf("%s\n%s", key, cert),
	})
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}
	d.SetId(backend)

	return pkiConfigCARead(d, meta)
}

func pkiConfigCARead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	secret, err := client.Logical().Read(backend + "/cert/ca")
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		d.SetId("")
		return nil
	}

	d.Set("ca", secret.Data["certificate"])

	return nil
}

func pkiConfigCaDelete(d *schema.ResourceData, meta interface{}) error {
	// There is nothing to actually delete
	return nil
}
