// Copyright IBM Corp. 2016, 2025
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
	consts.FieldGranularity,
	consts.FieldRegion,
	consts.FieldCustomTags,
	consts.FieldSecretNameTemplate,
	consts.FieldRoleArn,
	consts.FieldExternalID,
}

// awsSyncReadFields contains all fields that are returned on read from the API
var awsSyncReadFields = []string{
	consts.FieldRegion,
	consts.FieldCustomTags,
	consts.FieldGranularity,
	consts.FieldSecretNameTemplate,
	consts.FieldRoleArn,
	consts.FieldExternalID,
}

func awsSecretsSyncDestinationResource() *schema.Resource {
	return provider.MustAddSecretsSyncCloudSchema(&schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(awsSecretsSyncDestinationCreateUpdate, provider.VaultVersion116),
		ReadContext:   provider.ReadContextWrapper(awsSecretsSyncDestinationRead),
		UpdateContext: awsSecretsSyncDestinationCreateUpdate,
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
			consts.FieldRoleArn: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a role to assume when connecting to AWS.",
			},
			consts.FieldExternalID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Extra protection that must match the trust policy granting access to the AWS IAM role ARN.",
			},
		},
	})
}

func awsSecretsSyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationCreateUpdate(ctx, d, meta, awsSyncType, awsSyncWriteFields, awsSyncReadFields)
}

func awsSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// since other fields come back as '******', we only set the non-sensitive region fields
	return syncutil.SyncDestinationRead(ctx, d, meta, awsSyncType, awsSyncReadFields, map[string]string{
		consts.FieldGranularity: consts.FieldGranularityLevel,
	})
}

func awsSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, awsSyncType)
}
