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

func pkiSecretBackendCertMetadataDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(readPKISecretBackendCertMetadata),
		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Full path where PKI backend is mounted.",
			},
			consts.FieldSerial: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the serial of the certificate whose metadata to read.",
			},
			consts.FieldIssuerID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the issuer.",
			},
			consts.FieldExpiration: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certificate expiration as a Unix-style timestamp.",
			},
			consts.FieldCertMetadata: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The metadata returned from Vault",
			},
			consts.FieldRole: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The role that issued the certificate",
			},
			consts.FieldSerialNumber: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certificate serial number",
			},
		},
	}
}

func readPKISecretBackendCertMetadata(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldPath).(string)
	serial := d.Get(consts.FieldSerial).(string)
	path := fmt.Sprintf("%s/cert-metadata/%s", backend, serial)

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	if resp == nil {
		return diag.FromErr(fmt.Errorf("no metadata found for cert %s", serial))
	}

	d.SetId(path)

	attributeFields := []string{
		consts.FieldIssuerID,
		consts.FieldExpiration,
		consts.FieldCertMetadata,
		consts.FieldRole,
		consts.FieldSerialNumber,
	}

	for _, f := range attributeFields {
		if v, ok := resp.Data[f]; ok {
			err = d.Set(f, v)
			if err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return nil
}
