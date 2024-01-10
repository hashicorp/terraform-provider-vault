// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/vault/helper/namespace"
)

const (
	fieldDisabled      = "disabled"
	fieldQueueCapacity = "queue_capacity"
)

var syncConfigFields = []string{
	fieldDisabled,
	fieldQueueCapacity,
}

func secretsSyncConfigResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(secretsSyncConfigWrite, provider.VaultVersion116),
		UpdateContext: secretsSyncConfigWrite,
		ReadContext:   secretsSyncConfigRead,
		DeleteContext: secretsSyncConfigDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			fieldDisabled: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Disables the syncing process between Vault and external destinations.",
			},
			fieldQueueCapacity: {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     1_000_000,
				Description: "Maximum number of pending sync operations allowed on the queue.",
			},
		},
	}
}

func secretsSyncConfigWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	if client.Namespace() != namespace.RootNamespaceID && client.Namespace() != "" {
		return diag.Errorf("error writing sync config, this API is reversed to the root namespace and cannot be used with %q", client.Namespace())
	}

	path := secretsSyncConfigPath()

	data := map[string]interface{}{}
	for _, k := range syncConfigFields {
		if value, ok := d.GetOk(k); ok {
			data[k] = value
		}
	}

	log.Printf("[DEBUG] Writing sync config at %q", path)
	_, err := client.Logical().JSONMergePatch(ctx, path, data)
	if err != nil {
		return diag.Errorf("error writing sync config at %q: %s", path, err)
	}

	d.SetId("global_config") // Config is global and doesn't have a human-defined identifier, so we use a placeholder ID

	return secretsSyncConfigRead(ctx, d, meta)
}

func secretsSyncConfigRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := secretsSyncConfigPath()

	log.Printf("[DEBUG] Reading sync config from %q", path)
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading sync config from %q: %s", path, err)
	}

	if resp == nil {
		log.Printf("[WARN] No config found at %q; removing from state.", path)
		d.SetId("")
		return nil
	}

	return nil
}

func secretsSyncConfigDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := secretsSyncConfigPath()

	log.Printf("[DEBUG] Resetting sync config to default values at %q", path)
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error deleting sync config at %q: %s", path, err)
	}

	d.SetId("")

	return nil
}

func secretsSyncConfigPath() string {
	return "sys/sync/config"
}
