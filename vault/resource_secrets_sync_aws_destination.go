// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/sync"
)

const (
	fieldAccessKeyID     = "access_key_id"
	fieldSecretAccessKey = "secret_access_key"

	awsSyncType = "aws-sm"
)

// awsSyncWriteFields contains all fields that need to be written to the API
var awsSyncWriteFields = []string{
	fieldAccessKeyID,
	fieldSecretAccessKey,
	consts.FieldRegion,
	consts.FieldCustomTags,
	consts.FieldSecretNameTemplate,
}

// awsSyncReadFields contains all fields that are returned on read from the API
var awsSyncReadFields = []string{
	consts.FieldRegion,
	consts.FieldCustomTags,
	consts.FieldSecretNameTemplate,
}

// awsSyncUpdateFields contains all fields that can be updated via the API
var awsSyncUpdateFields = []string{
	fieldAccessKeyID,
	fieldSecretAccessKey,
}

func awsSecretsSyncDestinationResource() *schema.Resource {
	return provider.MustAddSecretsSyncCloudSchema(&schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(awsSecretsSyncDestinationWrite, provider.VaultVersion116),
		ReadContext:   provider.ReadContextWrapper(awsSecretsSyncDestinationRead),
		UpdateContext: awsSecretsSyncDestinationUpdate,
		DeleteContext: awsSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the AWS destination.",
				ForceNew:    true,
			},
			fieldAccessKeyID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Access key id to authenticate against the AWS secrets manager.",
			},
			fieldSecretAccessKey: {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Description: "Secret access key to authenticate against the AWS secrets " +
					"manager.",
			},
			consts.FieldRegion: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Region where to manage the secrets manager entries.",
				ForceNew:    true,
			},
		},
	})
}

func awsSecretsSyncDestinationWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationWrite(ctx, d, meta, awsSyncType, awsSyncWriteFields, awsSyncReadFields)
}

func awsSecretsSyncDestinationUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationUpdate(ctx, d, meta, awsSyncType, awsSyncUpdateFields, awsSyncReadFields)
}

func awsSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// since other fields come back as '******', we only set the non-sensitive region fields
	return syncutil.SyncDestinationRead(ctx, d, meta, awsSyncType, awsSyncReadFields)
}

func awsSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, awsSyncType)
}
