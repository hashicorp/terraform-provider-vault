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
	fieldAccessToken     = "access_token"
	fieldRepositoryOwner = "repository_owner"
	fieldRepositoryName  = "repository_name"
	ghSyncType           = "gh"
)

var githubSyncWriteFields = []string{
	fieldAccessToken,
	fieldRepositoryOwner,
	fieldRepositoryName,
	consts.FieldSecretNameTemplate,
}

var githubSyncUpdateFields = []string{
	fieldAccessToken,
}

var githubSyncReadFields = []string{
	fieldRepositoryOwner,
	fieldRepositoryName,
	consts.FieldSecretNameTemplate,
}

func githubSecretsSyncDestinationResource() *schema.Resource {
	return provider.MustAddSecretsSyncCommonSchema(&schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(githubSecretsSyncDestinationWrite, provider.VaultVersion116),
		ReadContext:   provider.ReadContextWrapper(githubSecretsSyncDestinationRead),
		UpdateContext: githubSecretsSyncDestinationUpdate,
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
	})
}

func githubSecretsSyncDestinationWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationWrite(ctx, d, meta, ghSyncType, githubSyncWriteFields, githubSyncReadFields)
}

func githubSecretsSyncDestinationUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationUpdate(ctx, d, meta, ghSyncType, githubSyncUpdateFields, githubSyncReadFields)
}

func githubSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationRead(ctx, d, meta, ghSyncType, githubSyncReadFields)
}

func githubSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, ghSyncType)
}
