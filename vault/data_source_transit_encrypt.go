// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func transitEncryptDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(transitEncryptDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldKey: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the encryption key to use.",
			},
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Transit secret backend the key belongs to.",
			},
			consts.FieldPlaintext: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},
			consts.FieldContext: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the context for key derivation",
			},
			consts.FieldKeyVersion: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The version of the key to use for encryption",
			},
			consts.FieldIV: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			consts.FieldCiphertext: {
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

	backend := d.Get(consts.FieldBackend).(string)
	key := d.Get(consts.FieldKey).(string)
	keyVersion := d.Get(consts.FieldKeyVersion).(int)
	iv := d.Get(consts.FieldIV).(string)

	plaintext := base64.StdEncoding.EncodeToString([]byte(d.Get("plaintext").(string)))
	context := base64.StdEncoding.EncodeToString([]byte(d.Get("context").(string)))
	payload := map[string]interface{}{
		consts.FieldPlaintext:  plaintext,
		consts.FieldContext:    context,
		consts.FieldKeyVersion: keyVersion,
		consts.FieldIV:         iv,
	}

	encryptedData, err := client.Logical().Write(backend+"/encrypt/"+key, payload)
	if err != nil {
		return fmt.Errorf("issue encrypting with key: %s", err)
	}

	cipherText := encryptedData.Data[consts.FieldCiphertext]

	d.SetId(base64.StdEncoding.EncodeToString([]byte(cipherText.(string))))
	d.Set(consts.FieldCiphertext, cipherText)

	return nil
}
