// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendIssuersDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(readPKISecretBackendIssuers),
		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where PKI backend is mounted.",
			},
			consts.FieldKeys: {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Keys used by issuers under the backend path.",
			},
			consts.FieldKeyInfo: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of issuer strings read from Vault.",
			},
			// we also save the key info as a JSON string in order to
			// cleanly support nested values
			consts.FieldKeyInfoJSON: {
				Type:     schema.TypeString,
				Computed: true,
				Description: "JSON-encoded key info key info data " +
					"read from Vault.",
			},
		},
	}
}

func readPKISecretBackendIssuers(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := fmt.Sprintf("%s/issuers", backend)

	resp, err := client.Logical().ListWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", path)
	if resp == nil {
		d.SetId("")
		return nil
	}

	d.SetId(path)

	if err := d.Set(consts.FieldKeys, resp.Data[consts.FieldKeys]); err != nil {
		return diag.FromErr(err)
	}

	if data, ok := resp.Data[consts.FieldKeyInfo]; ok {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return diag.Errorf("error marshaling JSON for %q: %s", path, err)
		}
		if err := d.Set(consts.FieldKeyInfoJSON, string(jsonData)); err != nil {
			return diag.FromErr(err)
		}

		if err := d.Set(consts.FieldKeyInfo, serializeDataMapToString(data.(map[string]interface{}))); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}
