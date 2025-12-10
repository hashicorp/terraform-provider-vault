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

func buildGCPSyncWriteFields(meta interface{}) []string {
	fields := []string{
		consts.FieldCredentials,
		consts.FieldGranularity,
		consts.FieldSecretNameTemplate,
		consts.FieldCustomTags,
		consts.FieldProjectID,
	}

	if provider.IsAPISupported(meta, provider.VaultVersion118) {
		fields = append(fields, consts.FieldReplicationLocations)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		fields = append(fields, []string{
			consts.FieldAllowedIPv4Addresses,
			consts.FieldAllowedIPv6Addresses,
			consts.FieldAllowedPorts,
			consts.FieldDisableStrictNetworking,
			consts.FieldLocationalKmsKeys,
			consts.FieldGlobalKmsKey,
		}...)
	}

	return fields
}

func buildGCPSyncReadFields(meta interface{}) []string {
	fields := []string{
		consts.FieldSecretNameTemplate,
		consts.FieldGranularity,
		consts.FieldCustomTags,
		consts.FieldProjectID,
	}

	if provider.IsAPISupported(meta, provider.VaultVersion118) {
		fields = append(fields, consts.FieldReplicationLocations)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		fields = append(fields, []string{
			consts.FieldAllowedIPv4Addresses,
			consts.FieldAllowedIPv6Addresses,
			consts.FieldAllowedPorts,
			consts.FieldDisableStrictNetworking,
			consts.FieldLocationalKmsKeys,
			consts.FieldGlobalKmsKey,
		}...)
	}

	return fields
}

func gcpSecretsSyncDestinationResource() *schema.Resource {
	return provider.MustAddSecretsSyncCloudSchema(&schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(gcpSecretsSyncDestinationCreateUpdate, provider.VaultVersion116),
		UpdateContext: gcpSecretsSyncDestinationCreateUpdate,
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
				Optional:    true,
				Sensitive:   true,
				Description: "JSON-encoded credentials to use to connect to GCP.",
			},
			consts.FieldProjectID: {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The target project to manage secrets in.",
			},
			consts.FieldAllowedIPv4Addresses: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Allowed IPv4 addresses for outbound network connectivity in CIDR notation. If not set, all IPv6 addresses are allowed.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldAllowedIPv6Addresses: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Allowed IPv6 addresses for outbound network connectivity in CIDR notation. If not set, all IPv6 addresses are allowed.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldAllowedPorts: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Allowed ports for outbound network connectivity. If not set, all ports are allowed.",
				Elem:        &schema.Schema{Type: schema.TypeInt},
			},
			consts.FieldDisableStrictNetworking: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Disable strict networking requirements.",
			},
			consts.FieldLocationalKmsKeys: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Locational KMS keys for encryption.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldGlobalKmsKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Global KMS key for encryption.",
			},
			consts.FieldReplicationLocations: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Replication locations for secrets.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	})
}

func gcpSecretsSyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	writeFields := buildGCPSyncWriteFields(meta)
	readFields := buildGCPSyncReadFields(meta)
	return syncutil.SyncDestinationCreateUpdate(ctx, d, meta, gcpSyncType, writeFields, readFields)
}

func gcpSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	readFields := buildGCPSyncReadFields(meta)
	return syncutil.SyncDestinationRead(ctx, d, meta, gcpSyncType, readFields, map[string]string{
		consts.FieldGranularity: consts.FieldGranularityLevel,
	})
}

func gcpSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, gcpSyncType)
}
