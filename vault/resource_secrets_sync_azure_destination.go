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

var azureSyncWriteFields = []string{
	fieldKeyVaultURI,
	fieldCloud,
	consts.FieldGranularity,
	consts.FieldSecretNameTemplate,
	consts.FieldCustomTags,
	consts.FieldClientSecret,
	consts.FieldClientID,
	consts.FieldTenantID,
}

var azureSyncReadFields = []string{
	fieldKeyVaultURI,
	fieldCloud,
	consts.FieldGranularity,
	consts.FieldSecretNameTemplate,
	consts.FieldCustomTags,
	consts.FieldClientID,
	consts.FieldTenantID,
}

// These fields are conditionally added to read and write operations when Vault 1.19+ is detected
var azureSyncFieldsV119 = []string{
	consts.FieldAllowedIPv4Addresses,
	consts.FieldAllowedIPv6Addresses,
	consts.FieldAllowedPorts,
	consts.FieldDisableStrictNetworking,
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
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	path := syncutil.SecretsSyncDestinationPath(name, azureSyncType)

	data := map[string]interface{}{}

	// Check if Vault 1.19+ fields are being used
	isV119Supported := provider.IsAPISupported(meta, provider.VaultVersion119)

	// Process base fields (all versions)
	for _, k := range azureSyncWriteFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	// Process Vault 1.19+ fields only if version is supported
	if isV119Supported {
		for _, k := range azureSyncFieldsV119 {
			if v, ok := d.GetOk(k); ok {
				// Handle TypeSet fields by converting to list
				switch k {
				case consts.FieldAllowedIPv4Addresses, consts.FieldAllowedIPv6Addresses, consts.FieldAllowedPorts:
					if set, ok := v.(*schema.Set); ok {
						data[k] = set.List()
					}
				default:
					data[k] = v
				}
			}
		}
	}

	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error writing sync destination data to %q: %s", path, err)
	}

	if d.IsNewResource() {
		d.SetId(name)
	}

	return azureSecretsSyncDestinationRead(ctx, d, meta)
}

func azureSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	readFields := make([]string, len(azureSyncReadFields))
	copy(readFields, azureSyncReadFields)

	// Add Vault 1.19+ fields if supported
	isV119Supported := provider.IsAPISupported(meta, provider.VaultVersion119)
	if isV119Supported {
		readFields = append(readFields, azureSyncFieldsV119...)
	}

	return syncutil.SyncDestinationRead(ctx, d, meta, azureSyncType, readFields, map[string]string{
		consts.FieldGranularity: consts.FieldGranularityLevel,
	})
}

func azureSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, azureSyncType)
}
