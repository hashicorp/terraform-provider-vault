// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldAccessToken     = "access_token"
	fieldRepositoryOwner = "repository_owner"
	fieldRepositoryName  = "repository_name"
)

var githubSyncDestinationFields = []string{
	fieldAccessToken,
	fieldRepositoryOwner,
	fieldRepositoryName,
}

var githubNonSensitiveFields = []string{
	fieldRepositoryOwner,
	fieldRepositoryName,
}

func githubSecretsSyncDestinationResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(githubSecretsSyncDestinationWrite, provider.VaultVersion115),
		ReadContext:   provider.ReadContextWrapper(githubSecretsSyncDestinationRead),
		DeleteContext: githubSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the github destination.",
				ForceNew:    true,
			},
			fieldAccessToken: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Fine-grained or personal access token.",
				ForceNew:    true,
			},
			fieldRepositoryOwner: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "GitHub organization or username that owns the repository.",
				ForceNew:    true,
			},
			fieldRepositoryName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the repository.",
				ForceNew:    true,
			},
		},
	}
}

func githubSecretsSyncDestinationWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	path := githubSecretsSyncDestinationPath(name)

	data := map[string]interface{}{}

	for _, k := range githubSyncDestinationFields {
		data[k] = d.Get(k)
	}

	log.Printf("[DEBUG] Writing Github sync destination to %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error enabling Github sync destination %q: %s", path, err)
	}
	log.Printf("[DEBUG] Enabled Github sync destination %q", path)

	d.SetId(name)

	return githubSecretsSyncDestinationRead(ctx, d, meta)
}

func githubSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	name := d.Id()
	path := githubSecretsSyncDestinationPath(name)

	log.Printf("[DEBUG] Reading Github sync destination")
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading Github sync destination from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Github sync destination")

	if resp == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range githubNonSensitiveFields {
		if data, ok := resp.Data[vaultFieldConnectionDetails]; ok {
			if m, ok := data.(map[string]interface{}); ok {
				if v, ok := m[k]; ok {
					if err := d.Set(k, v); err != nil {
						return diag.Errorf("error setting state key %q: err=%s", k, err)
					}
				}
			}
		}
	}

	return nil
}

func githubSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := githubSecretsSyncDestinationPath(d.Id())

	log.Printf("[DEBUG] Deleting Github sync destination at %q", path)
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error deleting Github sync destination at %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted Github sync destination at %q", path)

	return nil
}

func githubSecretsSyncDestinationPath(name string) string {
	return "sys/sync/destinations/gh/" + name
}
