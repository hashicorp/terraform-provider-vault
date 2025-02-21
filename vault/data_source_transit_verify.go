// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/hashicorp/terraform-provider-vault/internal/consts"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
				Computed:    true,
				Description: "Indicates whether verification succeeded",
			},
			consts.FieldBatchResults: {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The results returned from Vault if using batch_input",
			},
		},
	}
}

func transitVerifyDataSourceRead(d *schema.ResourceData, meta interface{}) error {

	return nil
}
