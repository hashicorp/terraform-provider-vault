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

func transitDecryptDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(transitDecryptDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldKey: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the decryption key to use.",
			},
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Transit secret backend the key belongs to.",
			},
			consts.FieldPlaintext: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Decrypted plain text",
				Sensitive:   true,
			},
			consts.FieldContext: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the context for key derivation",
			},
			consts.FieldCiphertext: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Transit encrypted cipher text.",
			},
		},
	}
}

func transitDecryptDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get(consts.FieldBackend).(string)
	key := d.Get(consts.FieldKey).(string)
	ciphertext := d.Get(consts.FieldCiphertext).(string)

	context := base64.StdEncoding.EncodeToString([]byte(d.Get("context").(string)))
	payload := map[string]interface{}{
		consts.FieldCiphertext: ciphertext,
		consts.FieldContext:    context,
	}

	decryptedData, err := client.Logical().Write(backend+"/decrypt/"+key, payload)
	if err != nil {
		return fmt.Errorf("issue encrypting with key: %s", err)
	}

	plaintext, _ := base64.StdEncoding.DecodeString(decryptedData.Data[consts.FieldPlaintext].(string))

	d.SetId(base64.StdEncoding.EncodeToString([]byte(ciphertext)))
	d.Set(consts.FieldPlaintext, string(plaintext))

	return nil
}
