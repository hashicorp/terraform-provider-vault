// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

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

	encryptedData, err := client.Logical().Write(backend+"/encrypt/"+key, payload)
	if err != nil {
		return fmt.Errorf("issue encrypting with key: %s", err)
	}

	cipherText := encryptedData.Data["ciphertext"]

	d.SetId(base64.StdEncoding.EncodeToString([]byte(cipherText.(string))))
	d.Set("ciphertext", cipherText)

	return nil
}
