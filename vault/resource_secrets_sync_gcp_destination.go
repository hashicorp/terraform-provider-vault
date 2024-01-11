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
	gcpSyncType = "gcp-sm"
)

var gcpSyncWriteFields = []string{
	consts.FieldCredentials,
	consts.FieldSecretNameTemplate,
	consts.FieldCustomTags,
}

var gcpSyncUpdateFields = []string{
	consts.FieldCredentials,
	// consts.FieldSecretNameTemplate,
	// consts.FieldCustomTags,
}

var gcpSyncReadFields = []string{
	consts.FieldSecretNameTemplate,
	consts.FieldCustomTags,
}

func gcpSecretsSyncDestinationResource() *schema.Resource {
	return provider.MustAddSecretsSyncCloudSchema(&schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(gcpSecretsSyncDestinationWrite, provider.VaultVersion116),
		UpdateContext: gcpSecretsSyncDestinationUpdate,
		ReadContext:   provider.ReadContextWrapper(gcpSecretsSyncDestinationRead),
		DeleteContext: gcpSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the GCP destination.",
				ForceNew:    true,
			},
			consts.FieldCredentials: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "JSON-encoded credentials to use to connect to GCP.",
			},
		},
	})
}

func gcpSecretsSyncDestinationWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationWrite(ctx, d, meta, gcpSyncType, gcpSyncWriteFields, gcpSyncReadFields)
}

func gcpSecretsSyncDestinationUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationUpdate(ctx, d, meta, gcpSyncType, gcpSyncUpdateFields, gcpSyncReadFields)
}

func gcpSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationRead(ctx, d, meta, gcpSyncType, gcpSyncReadFields)
}

func gcpSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, gcpSyncType)
}
