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
	fieldKeyVaultURI = "key_vault_uri"
	fieldCloud       = "cloud"
	azureSyncType    = "azure-kv"
)

func buildAzureSyncWriteFields(meta interface{}) []string {
	fields := []string{
		fieldKeyVaultURI,
		fieldCloud,
		consts.FieldGranularity,
		consts.FieldSecretNameTemplate,
		consts.FieldCustomTags,
		consts.FieldClientSecret,
		consts.FieldClientID,
		consts.FieldTenantID,
	}

	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		fields = append(fields, []string{
			consts.FieldAllowedIPv4Addresses,
			consts.FieldAllowedIPv6Addresses,
			consts.FieldAllowedPorts,
			consts.FieldDisableStrictNetworking,
		}...)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion200) {
		fields = append(fields,
			consts.FieldIdentityTokenAudience,
			consts.FieldIdentityTokenTTL,
			consts.FieldIdentityTokenKey,
		)
	}

	return fields
}

func buildAzureSyncReadFields(meta interface{}) []string {
	fields := []string{
		fieldKeyVaultURI,
		fieldCloud,
		consts.FieldGranularity,
		consts.FieldSecretNameTemplate,
		consts.FieldCustomTags,
		consts.FieldClientID,
		consts.FieldTenantID,
	}

	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		fields = append(fields, []string{
			consts.FieldAllowedIPv4Addresses,
			consts.FieldAllowedIPv6Addresses,
			consts.FieldAllowedPorts,
			consts.FieldDisableStrictNetworking,
		}...)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion200) {
		fields = append(fields,
			consts.FieldIdentityTokenTTL,
		)
	}

	return fields
}

// Fields that need TypeSet to List conversion for JSON serialization
var azureTypeSetFields = map[string]bool{
	consts.FieldAllowedIPv4Addresses: true,
	consts.FieldAllowedIPv6Addresses: true,
	consts.FieldAllowedPorts:         true,
}

func azureSecretsSyncDestinationResource() *schema.Resource {
	return provider.MustAddSecretsSyncCloudSchema(&schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(azureSecretsSyncDestinationCreateUpdate, provider.VaultVersion115),
		ReadContext:   provider.ReadContextWrapper(azureSecretsSyncDestinationRead),
		UpdateContext: azureSecretsSyncDestinationCreateUpdate,
		DeleteContext: azureSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the Azure destination.",
				ForceNew:    true,
			},
			fieldKeyVaultURI: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URI of an existing Azure Key Vault instance.",
				ForceNew:    true,
			},
			consts.FieldClientID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client ID of an Azure app registration.",
			},
			consts.FieldClientSecret: {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Client Secret of an Azure app registration.",
			},
			consts.FieldTenantID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ID of the target Azure tenant.",
				ForceNew:    true,
			},
			consts.FieldIdentityTokenKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The key to use for signing identity tokens.",
			},
			consts.FieldIdentityTokenAudience: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The audience claim value for identity tokens.",
			},
			consts.FieldIdentityTokenTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The TTL of generated tokens.",
			},
			fieldCloud: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a cloud for the client.",
				ForceNew:    true,
			},
			consts.FieldAllowedIPv4Addresses: {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Description: "Set of allowed IPv4 addresses in CIDR notation (e.g., 192.168.1.1/32) " +
					"for outbound connections from Vault to the destination. If not set, all IPv4 addresses are allowed. " +
					"Requires Vault 1.19+.",
			},
			consts.FieldAllowedIPv6Addresses: {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Description: "Set of allowed IPv6 addresses in CIDR notation (e.g., 2001:db8::1/128) " +
					"for outbound connections from Vault to the destination. If not set, all IPv6 addresses are allowed. " +
					"Requires Vault 1.19+.",
			},
			consts.FieldAllowedPorts: {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeInt},
				Optional: true,
				Description: "Set of allowed ports for outbound connections from Vault to the destination. " +
					"If not set, all ports are allowed. Requires Vault 1.19+.",
			},
			consts.FieldDisableStrictNetworking: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
				Description: "If set to true, disables strict networking enforcement for this destination. " +
					"When disabled, Vault will not enforce allowed IP addresses and ports. Requires Vault 1.19+.",
			},
		},
	})
}

func azureSecretsSyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	writeFields := buildAzureSyncWriteFields(meta)
	readFields := buildAzureSyncReadFields(meta)
	return syncutil.SyncDestinationCreateUpdateWithOptions(ctx, d, meta, azureSyncType, writeFields, readFields, azureTypeSetFields)
}

func azureSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	readFields := buildAzureSyncReadFields(meta)
	return syncutil.SyncDestinationRead(ctx, d, meta, azureSyncType, readFields, map[string]string{
		consts.FieldGranularity: consts.FieldGranularityLevel,
	})
}

func azureSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, azureSyncType)
}
