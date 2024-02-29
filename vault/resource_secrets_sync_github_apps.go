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

const (
	fieldFingerprint = "fingerprint"
)

var githubAppsSyncWriteFields = []string{
	consts.FieldName,
	consts.FieldAppID,
	consts.FieldPrivateKey,
}

var githubAppsSyncReadFields = []string{
	consts.FieldName,
	consts.FieldAppID,
	//fieldFingerprint,
}

func githubAppsSecretsSyncResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(githubAppsSecretsSyncCreateUpdate, provider.VaultVersion116),
		ReadContext:   provider.ReadContextWrapper(githubAppsSecretsSyncRead),
		UpdateContext: githubAppsSecretsSyncCreateUpdate,
		DeleteContext: githubAppsSecretsSyncDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The user-defined name of the GitHub App configuration.",
				ForceNew:    true,
			},
			consts.FieldAppID: {
				Type:        schema.TypeInt,
				Required:    true,
				ForceNew:    true,
				Description: "The GitHub application ID.",
			},
			consts.FieldPrivateKey: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "The content of a PEM formatted private key generated on GitHub for the app.",
			},
		},
	}
}

func githubAppsSecretsSyncCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	path := secretsSyncGitHubAppsPath(name)

	data := map[string]interface{}{}

	for _, k := range githubAppsSyncWriteFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	log.Printf("[DEBUG] Writing github-apps data to %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error writing github-apps data to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote github-apps data to %q", path)

	if d.IsNewResource() {
		d.SetId(name)
	}

	return githubAppsSecretsSyncRead(ctx, d, meta)
}

func githubAppsSecretsSyncRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	name := d.Id()
	path := secretsSyncGitHubAppsPath(name)

	log.Printf("[DEBUG] Reading sync github-apps")
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading sync github-apps from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read sync")

	if resp == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range githubAppsSyncReadFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return nil
}

func githubAppsSecretsSyncDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := secretsSyncGitHubAppsPath(d.Id())

	log.Printf("[DEBUG] Deleting sync github-apps at %q", path)
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error deleting github-apps sync at %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted github-apps sync at %q", path)

	return nil
}

func secretsSyncGitHubAppsPath(name string) string {
	return fmt.Sprintf("sys/sync/github-apps/%s", name)
}
