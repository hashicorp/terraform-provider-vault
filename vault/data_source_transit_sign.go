// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func transitSignDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(transitSignDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Transit secret backend the key belongs to.",
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the signing key to use.",
			},
			consts.FieldHashAlgorithm: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the hash algorithm to use for supporting key types (notably, not including ed25519 which specifies its own hash algorithm).",
			},
			consts.FieldKeyVersion: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The version of the key to use",
			},
			consts.FieldInput: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the base64 encoded input data. One of input or batch_input must be supplied.",
			},
			consts.FieldReference: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A user-supplied string that will be present in the reference field on the corresponding batch_results item in the response, to assist in understanding which result corresponds to a particular input. Only valid on batch requests when using ‘batch_input’ below.",
			},
			consts.FieldBatchInput: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specifies a list of items for processing. When this parameter is set, any supplied 'input' or 'context' parameters will be ignored. Responses are returned in the 'batch_results' array component of the 'data' element of the response. Any batch output will preserve the order of the batch input. If the input data value of an item is invalid, the corresponding item in the 'batch_results' will have the key 'error' with a value describing the error.",
				Elem:        &schema.Schema{Type: schema.TypeMap},
			},
			consts.FieldContext: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base64 encoded context for key derivation. Required if key derivation is enabled; currently only available with ed25519 keys.",
			},
			consts.FieldPrehashed: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Set to true when the input is already hashed. If the key type is rsa-2048, rsa-3072 or rsa-4096, then the algorithm used to hash the input should be indicated by the hash_algorithm parameter. Just as the value to sign should be the base64-encoded representation of the exact binary data you want signed, when set, input is expected to be base64-encoded binary hashed data, not hex-formatted. (As an example, on the command line, you could generate a suitable input via openssl dgst -sha256 -binary | base64.)",
			},
			consts.FieldSignatureAlgorithm: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "When using a RSA key, specifies the RSA signature algorithm to use for signing.",
			},
			consts.FieldMarshalingAlgorithm: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the way in which the signature should be marshaled. This currently only applies to ECDSA keys.",
			},
			consts.FieldSaltLength: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The salt length used to sign. This currently only applies to the RSA PSS signature scheme.",
			},
			consts.FieldSignature: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The signature returned from Vault if using input",
			},
			consts.FieldBatchResults: {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "The results returned from Vault if using batch_input",
				Elem:        &schema.Schema{Type: schema.TypeMap},
			},
		},
	}
}

func transitSignDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get(consts.FieldPath).(string)
	keyName := d.Get(consts.FieldName).(string)

	payload := map[string]interface{}{}

	signAPIStringFields := []string{
		consts.FieldKeyVersion,
		consts.FieldHashAlgorithm,
		consts.FieldInput,
		consts.FieldReference,
		consts.FieldContext,
		consts.FieldPrehashed,
		consts.FieldSignatureAlgorithm,
		consts.FieldMarshalingAlgorithm,
		consts.FieldSaltLength,
		consts.FieldBatchInput,
	}

	for _, f := range signAPIStringFields {
		if v, ok := d.GetOk(f); ok {
			payload[f] = v
		}
	}

	prehashed, ok := d.GetOk(consts.FieldPrehashed)
	if ok {
		payload[consts.FieldPrehashed] = prehashed.(bool)
	}

	reqPath := fmt.Sprintf("%s/sign/%s", path, keyName)
	resp, err := client.Logical().Write(reqPath, payload)
	if err != nil {
		return fmt.Errorf("error signing with key: %s", err)
	}

	d.SetId(reqPath)
	if batchResults, ok := resp.Data[consts.FieldBatchResults]; ok {
		err = d.Set(consts.FieldBatchResults, batchResults)
		if err != nil {
			return err
		}
	}

	if sig, ok := resp.Data[consts.FieldSignature]; ok {
		err = d.Set(consts.FieldSignature, sig)
		if err != nil {
			return err
		}
	}

	return nil
}
