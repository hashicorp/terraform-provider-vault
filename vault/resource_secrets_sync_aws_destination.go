// Copyright IBM Corp. 2016, 2025
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
	fieldAccessKeyID     = "access_key_id"
	fieldSecretAccessKey = "secret_access_key"

	awsSyncType = "aws-sm"
)

// awsSyncWriteFields contains base fields that work with all Vault versions (1.16+)
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

// awsSyncReadFields contains base fields that are returned on read from the API (all versions)
var awsSyncReadFields = []string{
	consts.FieldRegion,
	consts.FieldCustomTags,
	consts.FieldGranularity,
	consts.FieldSecretNameTemplate,
	consts.FieldRoleArn,
	consts.FieldExternalID,
}

// awsSync119Fields contains fields that require Vault 1.19+
var awsSync119Fields = []string{
	consts.FieldAllowedIPv4Addresses,
	consts.FieldAllowedIPv6Addresses,
	consts.FieldAllowedPorts,
	consts.FieldDisableStrictNetworking,
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
			consts.FieldAllowedIPv4Addresses: {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Allowed IPv4 addresses for outbound connections from Vault to AWS Secrets Manager. " +
					"Can also be set via an IP address range using CIDR notation.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldAllowedIPv6Addresses: {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Allowed IPv6 addresses for outbound connections from Vault to AWS Secrets Manager. " +
					"Can also be set via an IP address range using CIDR notation.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldAllowedPorts: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Allowed ports for outbound connections from Vault to AWS Secrets Manager.",
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
			},
			consts.FieldDisableStrictNetworking: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
				Description: "Disable strict networking mode. When set to true, " +
					"Vault will not enforce allowed IP addresses and ports.",
			},
		},
	})
}

func awsSecretsSyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	readFields := awsSyncReadFields
	writeFields := awsSyncWriteFields

	// Add Vault 1.19+ fields if supported
	isVaultVersion119 := provider.IsAPISupported(meta, provider.VaultVersion119)
	if isVaultVersion119 {
		writeFields = append(writeFields, awsSync119Fields...)
		readFields = append(readFields, awsSync119Fields...)
	}

	// Fields that need TypeSet to List conversion for JSON serialization
	awsTypeSetFields := make(map[string]bool)
	if isVaultVersion119 {
		awsTypeSetFields[consts.FieldAllowedIPv4Addresses] = true
		awsTypeSetFields[consts.FieldAllowedIPv6Addresses] = true
		awsTypeSetFields[consts.FieldAllowedPorts] = true
	}

	return syncutil.SyncDestinationCreateUpdateWithOptions(ctx, d, meta, awsSyncType, writeFields, readFields, awsTypeSetFields)
}

func awsSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// Start with base fields (all versions)
	readFields := awsSyncReadFields

	// Add Vault 1.19+ fields only if version is supported
	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		readFields = append(readFields, awsSync119Fields...)
	}

	// since other fields come back as '******', we only set the non-sensitive region fields
	return syncutil.SyncDestinationRead(ctx, d, meta, awsSyncType, readFields, map[string]string{
		consts.FieldGranularity: consts.FieldGranularityLevel,
	})
}

func awsSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, awsSyncType)
}
