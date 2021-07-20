package vault

import (
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func transitDecryptDataSource() *schema.Resource {
	return &schema.Resource{
		Read: transitDecryptDataSourceRead,

		Schema: map[string]*schema.Schema{
			"key": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the decryption key to use.",
			},
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Transit secret backend the key belongs to.",
			},
			"plaintext": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Decrypted plain text",
				Sensitive:   true,
			},
			"context": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the context for key derivation",
			},
			"ciphertext": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Transit encrypted cipher text.",
			},
		},
	}
}

func transitDecryptDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	key := d.Get("key").(string)
	ciphertext := d.Get("ciphertext").(string)

	context := base64.StdEncoding.EncodeToString([]byte(d.Get("context").(string)))
	payload := map[string]interface{}{
		"ciphertext": ciphertext,
		"context":    context,
	}

	decryptedData, err := client.Logical().Write(backend+"/decrypt/"+key, payload)
	if err != nil {
		return fmt.Errorf("issue encrypting with key: %s", err)
	}

	plaintext, _ := base64.StdEncoding.DecodeString(decryptedData.Data["plaintext"].(string))

	d.SetId(base64.StdEncoding.EncodeToString([]byte(ciphertext)))
	d.Set("plaintext", string(plaintext))

	return nil
}
