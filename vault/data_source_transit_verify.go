// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func transitVerifyDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(transitVerifyDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Transit secret backend the key belongs to.",
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the name of the encryption key that was used to generate the signature or HMAC.",
			},
			consts.FieldHashAlgorithm: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "sha2-256",
				Description: "Specifies the hash algorithm to use.",
			},
			consts.FieldInput: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the base64 encoded input data. One of input or batch_input must be supplied.",
			},
			consts.FieldSignature: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the signature output from the /transit/sign function. One of the following arguments must be supplied signature, hmac or cmac.",
			},
			consts.FieldHMAC: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the signature output from the /transit/hmac function. One of the following arguments must be supplied signature, hmac or cmac.",
			},
			consts.FieldCMAC: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "(Enterprise only) Specifies the signature output from the /transit/cmac function. One of the following arguments must be supplied signature, hmac or cmac.",
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
			consts.FieldSignatureContext: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `Base64 encoded context for Ed25519ctx and Ed25519ph signatures.`,
			},
			consts.FieldPrehashed: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Set to true when the input is already hashed. If the key type is rsa-2048, rsa-3072 or rsa-4096, then the algorithm used to hash the input should be indicated by the hash_algorithm parameter. Just as the value to sign should be the base64-encoded representation of the exact binary data you want signed, when set, input is expected to be base64-encoded binary hashed data, not hex-formatted. (As an example, on the command line, you could generate a suitable input via openssl dgst -sha256 -binary | base64.)",
			},
			consts.FieldSignatureAlgorithm: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "pss",
				Description: "When using a RSA key, specifies the RSA signature algorithm to use for signature verification.",
			},
			consts.FieldMarshalingAlgorithm: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "asn1",
				Description: "Specifies the way in which the signature was originally marshaled. This currently only applies to ECDSA keys.",
			},
			consts.FieldSaltLength: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "auto",
				Description: "The salt length used to sign. This currently only applies to the RSA PSS signature scheme.",
			},
			consts.FieldValid: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Indicates whether verification succeeded",
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

func transitVerifyDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get(consts.FieldPath).(string)
	keyName := d.Get(consts.FieldName).(string)

	payload := map[string]interface{}{}

	verifyAPIStringFields := []string{
		consts.FieldHashAlgorithm,
		consts.FieldInput,
		consts.FieldSignature,
		consts.FieldHMAC,
		consts.FieldCMAC,
		consts.FieldReference,
		consts.FieldBatchInput,
		consts.FieldContext,
		consts.FieldSignatureContext,
		consts.FieldPrehashed,
		consts.FieldSignatureAlgorithm,
		consts.FieldMarshalingAlgorithm,
		consts.FieldSaltLength,
	}

	for _, f := range verifyAPIStringFields {
		if v, ok := d.GetOk(f); ok {
			payload[f] = v
		}
	}

	prehashed, ok := d.GetOk(consts.FieldPrehashed)
	if ok {
		payload[consts.FieldPrehashed] = prehashed.(bool)
	}

	reqPath := fmt.Sprintf("%s/verify/%s", path, keyName)
	resp, err := client.Logical().Write(reqPath, payload)
	if err != nil {
		return fmt.Errorf("error signing with key: %s", err)
	}

	d.SetId(reqPath)

	rawBatchResults, batchOK := resp.Data[consts.FieldBatchResults]
	valid, validOK := resp.Data[consts.FieldSignature]

	if batchOK {
		batchResults, err := convertBatchResults(rawBatchResults)
		if err != nil {
			return err
		}

		err = d.Set(consts.FieldBatchResults, batchResults)
		if err != nil {
			return err
		}
	} else if validOK {
		err = d.Set(consts.FieldValid, valid)
		if err != nil {
			return err
		}
	} else {
		return errors.New("response contained neither batch_results field nor valid field")
	}

	return nil
}

// The code that does the parsing for maps will panic if given a map with a mix of boolean
// and string values. This function converts booleans to strings to avoid the error.
func convertBatchResults(rawResults interface{}) ([]map[string]interface{}, error) {
	batchResultsList, ok := rawResults.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected batch_results type %T", rawResults)
	}

	var batchResults []map[string]interface{}
	for _, result := range batchResultsList {
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected element type %T", result)
		}

		stringMap := make(map[string]interface{})
		for k, v := range resultMap {
			switch v.(type) {
			case bool:
				stringMap[k] = strconv.FormatBool(v.(bool))
			default:
				stringMap[k] = v
			}
		}
	}

	return batchResults, nil
}
