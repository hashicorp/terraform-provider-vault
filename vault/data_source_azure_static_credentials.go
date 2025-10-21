// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const azureStaticCredsAffix = "static-creds"

func azureStaticAccessCredentialsDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(azureStaticCredentialsDataSourceRead),
		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Azure Secret Backend to read credentials from.",
			},
			consts.FieldRole: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role to create",
				ForceNew:    true,
			},
			consts.FieldClientID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Client ID of an Azure app registration.",
			},
			consts.FieldClientSecret: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Client secret of the Azure app registration.",
				Sensitive:   true,
			},
			consts.FieldSecretID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Secret ID of the Azure app registration.",
			},
			consts.FieldMetadata: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Metadata associated with the secret.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldExpiration: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Expiration time of the credential",
			},
		},
	}
}

var azureSecretBackendStaticCredsFields = []string{
	consts.FieldClientSecret,
	consts.FieldClientID,
	consts.FieldSecretID,
}

func azureStaticCredentialsDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	role := d.Get(consts.FieldRole).(string)
	fullPath := fmt.Sprintf("%s/%s/%s", backend, azureStaticCredsAffix, role)

	secret, err := client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", fullPath)
	if secret == nil {
		return diag.FromErr(fmt.Errorf("no role found at %q", fullPath))
	}

	d.SetId(fullPath)

	useAPIVer121Ent := provider.IsAPISupported(meta, provider.VaultVersion121) && provider.IsEnterpriseSupported(meta)
	if useAPIVer121Ent {
		for _, field := range azureSecretBackendStaticCredsFields {
			if v, ok := secret.Data[field]; ok {
				if err := d.Set(field, v); err != nil {
					return diag.FromErr(err)
				}
			}
		}
		if v, ok := secret.Data[consts.FieldMetadata]; ok {
			if err := NormalizeMap(d, consts.FieldMetadata, v); err != nil {
				return diag.FromErr(err)
			}
		}
		if v, ok := secret.Data[consts.FieldExpiration]; ok {
			if exp, ok := v.(time.Time); ok {
				if err := d.Set(consts.FieldExpiration, exp.UTC().Format(time.RFC3339)); err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}

	return nil
}
