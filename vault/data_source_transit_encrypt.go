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

func transitEncryptDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(transitEncryptDataSourceRead),

		Schema: map[string]*schema.Schema{
			"key": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the encryption key to use.",
			},
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Transit secret backend the key belongs to.",
			},
			"plaintext": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},
			"context": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the context for key derivation",
			},
			"key_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The version of the key to use for encryption",
			},
			consts.FieldHashAlgorithm: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "Specifies the hash algorithm to use for RSA key encryption. " +
					"Only applies to RSA key types; ignored for all other key types. " +
					"Supported values are: sha1, sha2-224, sha2-256, sha2-384, sha2-512, sha3-224, sha3-256, sha3-384, sha3-512. " +
					"If not set, Vault defaults to sha2-256 for RSA keys.",
				ValidateDiagFunc: provider.GetValidateDiagChoices([]string{"sha1", "sha2-224", "sha2-256", "sha2-384", "sha2-512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"}),
			},
			consts.FieldPaddingScheme: {
				Type:             schema.TypeString,
				Optional:         true,
				Computed:         true,
				Description:      "Specifies the RSA padding scheme to use for encryption. Only applies to RSA key types; ignored for all other key types. Supported values are: oaep, pkcs1v15. If not set, Vault defaults to oaep for RSA keys.",
				ValidateDiagFunc: provider.GetValidateDiagChoices([]string{"oaep", "pkcs1v15"}),
			},
			"ciphertext": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Transit encrypted cipher text.",
			},
		},
	}
}

func transitEncryptDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	key := d.Get("key").(string)
	keyVersion := d.Get("key_version").(int)

	plaintext := base64.StdEncoding.EncodeToString([]byte(d.Get("plaintext").(string)))
	context := base64.StdEncoding.EncodeToString([]byte(d.Get("context").(string)))
	payload := map[string]interface{}{
		"plaintext":   plaintext,
		"context":     context,
		"key_version": keyVersion,
	}

	if v, ok := d.GetOk(consts.FieldHashAlgorithm); ok {
		payload[consts.FieldHashAlgorithm] = v.(string)
	}
	if v, ok := d.GetOk(consts.FieldPaddingScheme); ok {
		payload[consts.FieldPaddingScheme] = v.(string)
	}

	encryptedData, err := client.Logical().Write(backend+"/encrypt/"+key, payload)
	if err != nil {
		return fmt.Errorf("issue encrypting with key: %s", err)
	}

	cipherText := encryptedData.Data["ciphertext"]

	d.SetId(base64.StdEncoding.EncodeToString([]byte(cipherText.(string))))
	d.Set("ciphertext", cipherText)

	return nil
}
