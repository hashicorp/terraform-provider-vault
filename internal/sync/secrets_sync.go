// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package syncutil

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldConnectionDetails = "connection_details"
	fieldOptions           = "options"
)

func SyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}, typ string, writeFields, readFields []string) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	path := SecretsSyncDestinationPath(name, typ)

	data := map[string]interface{}{}

	for _, k := range writeFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	log.Printf("[DEBUG] Writing sync destination data to %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error writing sync destination data to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote sync destination data to %q", path)

	if d.IsNewResource() {
		d.SetId(name)
	}

	return SyncDestinationRead(ctx, d, meta, typ, readFields, nil)
}

func SyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}, typ string, fields []string, vaultSchemaMap map[string]string) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	name := d.Id()
	path := SecretsSyncDestinationPath(name, typ)

	log.Printf("[DEBUG] Reading sync destination")
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading sync destination from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read sync destination")

	if resp == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	// implicitly set type, so it can be passed down to association resource for ease-of-use
	if err := d.Set(consts.FieldType, typ); err != nil {
		return diag.FromErr(err)
	}

	connectionDetails := resp.Data[fieldConnectionDetails]
	options := resp.Data[fieldOptions]
	for _, k := range fields {
		// field that Vault returns in response
		vaultKey := k

		if vaultSchemaMap != nil {
			if v, ok := vaultSchemaMap[k]; ok {
				// Vault uses a different key than the one in TF schema
				vaultKey = v
			}
		}

		if connectionMap, ok := connectionDetails.(map[string]interface{}); ok {
			if v, ok := connectionMap[vaultKey]; ok {
				if err := d.Set(k, v); err != nil {
					return diag.Errorf("error setting state key %q: err=%s", k, err)
				}
			}
		}

		if optionsMap, ok := options.(map[string]interface{}); ok {
			if v, ok := optionsMap[vaultKey]; ok {
				if err := d.Set(k, v); err != nil {
					return diag.Errorf("error setting state key %q: err=%s", k, err)
				}
			}
		}
	}

	return nil
}

func SyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}, typ string) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := SecretsSyncDestinationPath(d.Id(), typ)

	log.Printf("[DEBUG] Deleting sync destination at %q", path)
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error deleting sync destination at %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted sync destination at %q", path)

	return nil
}

func SecretsSyncDestinationPath(name, typ string) string {
	return fmt.Sprintf("sys/sync/destinations/%s/%s", typ, name)
}
