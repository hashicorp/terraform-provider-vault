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
	consts.FieldClientSecret,
	consts.FieldClientID,
	consts.FieldTenantID,
}

var azureSyncUpdateFields = []string{
	consts.FieldClientSecret,
	consts.FieldClientID,
}

var azureSyncReadFields = []string{
	fieldCloud,
	consts.FieldClientID,
	consts.FieldTenantID,
}

func azureSecretsSyncDestinationResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(azureSecretsSyncDestinationWrite, provider.VaultVersion115),
		ReadContext:   provider.ReadContextWrapper(azureSecretsSyncDestinationRead),
		// @TODO confirm this is available
		UpdateContext: azureSecretsSyncDestinationUpdate,
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
				Required:    true,
				Description: "URI of an existing Azure Key Vault instance.",
				ForceNew:    true,
			},
			consts.FieldClientID: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Client ID of an Azure app registration.",
			},
			consts.FieldClientSecret: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Client Secret of an Azure app registration.",
			},
			consts.FieldTenantID: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the target Azure tenant.",
				ForceNew:    true,
			},
			fieldCloud: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a cloud for the client.",
				ForceNew:    true,
			},
		},
	}
}

func azureSecretsSyncDestinationWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationWrite(ctx, d, meta, azureSyncType, azureSyncWriteFields, azureSyncReadFields)
}

func azureSecretsSyncDestinationUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationUpdate(ctx, d, meta, azureSyncType, azureSyncUpdateFields, azureSyncReadFields)
}

func azureSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationRead(ctx, d, meta, azureSyncType, azureSyncReadFields)
}

func azureSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, azureSyncType)
}
