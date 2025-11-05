// Copyright (c) HashiCorp, Inc.
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

const databaseStaticCredsAffix = "static-creds"

func databaseStaticCredDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(databaseStaticCredentialsDataSourceRead),
		Schema: map[string]*schema.Schema{
			// backend is deprecated, but the other database resource types use it, and predate the deprecation.
			// It's probably more helpful to the end user to maintain this consistency, in this particular case.
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "database Secret Backend to read credentials from.",
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role.",
			},
			consts.FieldUsername: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "database username read from Vault.",
				Sensitive:   true,
			},
			consts.FieldPassword: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "database password read from Vault.",
				Sensitive:   true,
			},
		},
	}
}

func databaseStaticCredentialsDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	role := d.Get(consts.FieldName).(string)
	fullPath := fmt.Sprintf("%s/%s/%s", backend, databaseStaticCredsAffix, role)

	secret, err := client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", fullPath)
	if secret == nil {
		return diag.FromErr(fmt.Errorf("no role found at %q", fullPath))
	}

	d.SetId(fullPath)

	if err := d.Set(consts.FieldUsername, secret.Data[consts.FieldUsername]); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldPassword, secret.Data[consts.FieldPassword]); err != nil {
		return diag.FromErr(err)
	}

	return nil
}
