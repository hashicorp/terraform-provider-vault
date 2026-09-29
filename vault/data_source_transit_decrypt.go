// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func transitDecryptDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(transitDecryptDataSourceRead),

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
			consts.FieldHashAlgorithm: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "Specifies the hash algorithm to use for RSA key decryption. " +
					"Only applies to RSA key types; ignored for all other key types. " +
					"Supported values are: sha1, sha2-224, sha2-256, sha2-384, sha2-512, sha3-224, sha3-256, sha3-384, sha3-512. " +
					"If not set, Vault defaults to sha2-256 for RSA keys.",
				ValidateDiagFunc: provider.GetValidateDiagChoices([]string{"sha1", "sha2-224", "sha2-256", "sha2-384", "sha2-512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"}),
			},
			consts.FieldPaddingScheme: {
				Type:             schema.TypeString,
				Optional:         true,
				Computed:         true,
				Description:      "Specifies the RSA padding scheme to use for decryption. Only applies to RSA key types; ignored for all other key types. Supported values are: oaep, pkcs1v15. If not set, Vault defaults to oaep for RSA keys.",
				ValidateDiagFunc: provider.GetValidateDiagChoices([]string{"oaep", "pkcs1v15"}),
			},
		},
	}
}

func transitDecryptDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	key := d.Get("key").(string)
	ciphertext := d.Get("ciphertext").(string)

	context := base64.StdEncoding.EncodeToString([]byte(d.Get("context").(string)))
	payload := map[string]interface{}{
		"ciphertext": ciphertext,
		"context":    context,
	}

	if v, ok := d.GetOk(consts.FieldHashAlgorithm); ok {
		payload[consts.FieldHashAlgorithm] = v.(string)
	}
	if v, ok := d.GetOk(consts.FieldPaddingScheme); ok {
		payload[consts.FieldPaddingScheme] = v.(string)
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
