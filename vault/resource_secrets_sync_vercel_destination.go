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
	fieldProjectID              = "project_id"
	fieldTeamID                 = "team_id"
	fieldDeploymentEnvironments = "deployment_environments"
	vercelSyncType              = "vercel-project"
)

var vercelSyncWriteFields = []string{
	fieldAccessToken,
	fieldProjectID,
	fieldTeamID,
	fieldDeploymentEnvironments,
	consts.FieldGranularity,
	consts.FieldSecretNameTemplate,
}

var vercelSyncReadFields = []string{
	fieldProjectID,
	fieldTeamID,
	fieldDeploymentEnvironments,
	consts.FieldGranularity,
	consts.FieldSecretNameTemplate,
}

// These fields are conditionally added to read and write operations when Vault 1.19+ is detected
var vercelSyncFieldsV119 = []string{
	consts.FieldAllowedIPv4Addresses,
	consts.FieldAllowedIPv6Addresses,
	consts.FieldAllowedPorts,
	consts.FieldDisableStrictNetworking,
}

func vercelSecretsSyncDestinationResource() *schema.Resource {
	return provider.MustAddSecretsSyncCommonSchema(&schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(vercelSecretsSyncDestinationCreateUpdate, provider.VaultVersion116),
		UpdateContext: vercelSecretsSyncDestinationCreateUpdate,
		ReadContext:   provider.ReadContextWrapper(vercelSecretsSyncDestinationRead),
		DeleteContext: vercelSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the Vercel destination.",
				ForceNew:    true,
			},
			fieldAccessToken: {
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: true,
				Description: "Vercel API access token with the permissions to manage " +
					"environment variables.",
			},
			fieldProjectID: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Project ID where to manage environment variables.",
				ForceNew:    true,
			},
			fieldTeamID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Team ID the project belongs to.",
			},
			fieldDeploymentEnvironments: {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Required: true,
				Description: "Deployment environments where the environment " +
					"variables are available. Accepts 'development', " +
					"'preview' & 'production'.",
			},
			consts.FieldAllowedIPv4Addresses: {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Description: "List of allowed IPv4 addresses in CIDR notation (e.g., 192.168.1.1/32) " +
					"for outbound connections from Vault to the destination. If not set, all IPv4 addresses are allowed.",
			},
			consts.FieldAllowedIPv6Addresses: {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Description: "List of allowed IPv6 addresses in CIDR notation (e.g., 2001:db8::1/128) " +
					"for outbound connections from Vault to the destination. If not set, all IPv6 addresses are allowed.",
			},
			consts.FieldAllowedPorts: {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeInt},
				Optional: true,
				Description: "List of allowed ports for outbound connections from Vault to the destination. " +
					"If not set, all ports are allowed.",
			},
			consts.FieldDisableStrictNetworking: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
				Description: "If set to true, disables strict networking enforcement for this destination. " +
					"When disabled, Vault will not enforce allowed IP addresses and ports.",
			},
		},
	})
}

func vercelSecretsSyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	writeFields := make([]string, len(vercelSyncWriteFields))
	copy(writeFields, vercelSyncWriteFields)
	readFields := make([]string, len(vercelSyncReadFields))
	copy(readFields, vercelSyncReadFields)

	// Add Vault 1.19+ fields if supported
	isV119Supported := provider.IsAPISupported(meta, provider.VaultVersion119)
	if isV119Supported {
		writeFields = append(writeFields, vercelSyncFieldsV119...)
		readFields = append(readFields, vercelSyncFieldsV119...)
	}

	return syncutil.SyncDestinationCreateUpdate(ctx, d, meta, vercelSyncType, writeFields, readFields)
}

func vercelSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	readFields := make([]string, len(vercelSyncReadFields))
	copy(readFields, vercelSyncReadFields)

	// Add Vault 1.19+ fields if supported
	isV119Supported := provider.IsAPISupported(meta, provider.VaultVersion119)
	if isV119Supported {
		readFields = append(readFields, vercelSyncFieldsV119...)
	}

	return syncutil.SyncDestinationRead(ctx, d, meta, vercelSyncType, readFields, map[string]string{
		consts.FieldGranularity: consts.FieldGranularityLevel,
	})
}

func vercelSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, vercelSyncType)
}
