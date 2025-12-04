// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func sshSecretBackendSignDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(readSSHBackendSign),
		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where SSH backend is mounted.",
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the name of the role to sign.",
			},
			consts.FieldPublicKey: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the SSH public key that should be signed.",
			},
			consts.FieldTTL: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the Requested Time To Live. Cannot be greater than the role's max_ttl value. If not provided, the role's ttl value will be used. Note that the role values default to system values if not explicitly set.",
			},
			consts.FieldValidPrincipals: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies valid principals, either usernames or hostnames, that the certificate should be signed for. Required unless the role has specified allow_empty_principals or a value has been set for either the default_user or default_user_template role parameters.",
			},
			consts.FieldCertType: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the type of certificate to be created; either \"user\" or \"host\".",
			},
			consts.FieldKeyID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the key id that the created certificate should have. If not specified, the display name of the token will be used.",
			},
			consts.FieldCriticalOptions: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Specifies a map of the critical options that the certificate should be signed for. Defaults to none.",
			},
			consts.FieldExtensions: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Specifies a map of the extensions that the certificate should be signed for. Defaults to none.",
			},
			consts.FieldSerialNumber: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The serial number of the certificate returned from Vault",
			},
			consts.FieldSignedKey: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The signed certificate returned from Vault",
			},
		},
	}
}

func readSSHBackendSign(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Get(consts.FieldPath).(string)
	name := d.Get(consts.FieldName).(string)

	signFields := []string{
		consts.FieldPublicKey,
		consts.FieldTTL,
		consts.FieldValidPrincipals,
		consts.FieldCertType,
		consts.FieldKeyID,
	}

	payload := map[string]interface{}{}

	for _, f := range signFields {
		if val, ok := d.GetOk(f); ok {
			payload[f] = val
		}
	}

	returnedData, err := client.Logical().WriteWithContext(ctx, fmt.Sprintf("%s/sign/%s", path, name), payload)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error signing key: %s", err))
	}

	serialNumber := returnedData.Data[consts.FieldSerialNumber]
	signedKey := returnedData.Data[consts.FieldSignedKey]

	d.SetId(serialNumber.(string))
	d.Set(consts.FieldSerialNumber, serialNumber)
	d.Set(consts.FieldSignedKey, signedKey)

	return nil
}
