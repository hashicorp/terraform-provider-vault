// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func kvSecretDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(kvSecretDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path of the KV-V1 secret.",
			},
			consts.FieldDataJSON: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON-encoded secret data read from Vault.",
				Sensitive:   true,
			},
			consts.FieldData: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},
			consts.FieldLeaseID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by Vault.",
			},
			consts.FieldLeaseDuration: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds.",
			},
			consts.FieldLeaseRenewable: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
		},
	}
}

func kvSecretDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)

	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading secret at %s from Vault", path)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading secret %q from Vault: %s", path, err)
	}
	if secret == nil {
		return diag.Errorf("no secret found at %q", path)
	}

	jsonData, err := json.Marshal(secret.Data)
	if err != nil {
		return diag.Errorf("error marshaling JSON for %q: %s", path, err)
	}

	if err := d.Set(consts.FieldDataJSON, string(jsonData)); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldData, serializeDataMapToString(secret.Data)); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldLeaseID, secret.LeaseID); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldLeaseDuration, secret.LeaseDuration); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldLeaseRenewable, secret.Renewable); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(path)

	return nil
}
