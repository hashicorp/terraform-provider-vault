// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const awsStaticCredsAffix = "static-creds"

func awsStaticCredDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(awsStaticCredentialsDataSourceRead),
		Schema: map[string]*schema.Schema{
			// backend is deprecated, but the other AWS resource types use it, and predate the deprecation.
			// It's probably more helpful to the end user to maintain this consistency, in this particular case.
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "AWS Secret Backend to read credentials from.",
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role.",
			},
			consts.FieldAccessKey: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS access key ID read from Vault.",
				Sensitive:   true,
			},
			consts.FieldSecretKey: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS secret key read from Vault.",
				Sensitive:   true,
			},
		},
	}
}

func awsStaticCredentialsDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	role := d.Get(consts.FieldName).(string)
	fullPath := fmt.Sprintf("%s/%s/%s", backend, awsStaticCredsAffix, role)

	secret, err := client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", fullPath)
	if secret == nil {
		return diag.FromErr(fmt.Errorf("no role found at %q", fullPath))
	}

	d.SetId(fullPath)

	if err := d.Set(consts.FieldAccessKey, secret.Data[consts.FieldAccessKey]); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldSecretKey, secret.Data[consts.FieldSecretKey]); err != nil {
		return diag.FromErr(err)
	}

	return nil
}
