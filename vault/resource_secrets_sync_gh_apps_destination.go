// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	syncutil "github.com/hashicorp/terraform-provider-vault/internal/sync"
)

const (
	ghAppsSyncType = "github-apps"
)

var githubAppsSyncWriteFields = []string{
	consts.FieldName,
	consts.FieldAppID,
	consts.FieldPrivateKey,
}

var githubAppsSyncReadFields = []string{
	consts.FieldName,
	consts.FieldAppID,
}

func githubAppsSecretsSyncDestinationResource() *schema.Resource {
	return provider.MustAddSecretsSyncCommonSchema(&schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(githubAppsSecretsSyncDestinationCreateUpdate, provider.VaultVersion116),
		ReadContext:   provider.ReadContextWrapper(githubAppsSecretsSyncDestinationRead),
		UpdateContext: githubAppsSecretsSyncDestinationCreateUpdate,
		DeleteContext: githubAppsSecretsSyncDestinationDelete,
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
			consts.FieldAppID: {
				Type:        schema.TypeInt,
				Required:    true,
				ForceNew:    true,
				Description: "The user-defined name of the GitHub App configuration.",
			},
			consts.FieldPrivateKey: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "The content of a PEM formatted private key generated on GitHub for the app.",
			},
		},
	})
}

func githubAppsSecretsSyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationCreateUpdate(ctx, d, meta, ghAppsSyncType, githubAppsSyncWriteFields, githubAppsSyncReadFields)
}

func githubAppsSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationRead(ctx, d, meta, ghAppsSyncType, githubAppsSyncReadFields)
}

func githubAppsSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, ghAppsSyncType)
}
