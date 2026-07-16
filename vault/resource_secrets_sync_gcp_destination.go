// Copyright IBM Corp. 2016, 2026
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

	if provider.IsAPISupported(meta, provider.VaultVersion200) {
		fields = append(fields,
			consts.FieldIdentityTokenAudience,
			consts.FieldIdentityTokenTTL,
			consts.FieldServiceAccountEmail,
			consts.FieldIdentityTokenKey,
		)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion210) {
		fields = append(fields,
			consts.FieldReplicaRegions,
			consts.FieldKmsKeyID,
		)
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

	if provider.IsAPISupported(meta, provider.VaultVersion200) {
		fields = append(fields,
			consts.FieldIdentityTokenTTL,
			consts.FieldServiceAccountEmail,
		)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion210) {
		fields = append(fields,
			consts.FieldReplicaRegions,
			consts.FieldKmsKeyID,
		)
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
			consts.FieldIdentityTokenKeyWO: {
				Type:        schema.TypeString,
				WriteOnly:   true,
				Sensitive:   true,
				Optional:    true,
				Description: "The key to use for signing identity tokens. This is a write-only field and will not be read back from Vault.",
			},
			consts.FieldIdentityTokenKeyWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "A version counter for the write-only identity_token_key_wo field. Incrementing this value will trigger an update.",
				RequiredWith: []string{consts.FieldIdentityTokenKeyWO},
			},
			consts.FieldIdentityTokenAudienceWO: {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Sensitive:   true,
				Description: "The audience claim value for identity tokens. This is a write-only field and will not be read back from Vault.",
			},
			consts.FieldIdentityTokenAudienceWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "A version counter for the write-only identity_token_audience_wo field. Incrementing this value will trigger an update.",
				RequiredWith: []string{consts.FieldIdentityTokenAudienceWO},
			},
			consts.FieldIdentityTokenTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The TTL of generated tokens.",
			},
			consts.FieldServiceAccountEmail: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Service Account to impersonate for workload identity federation.",
			},
			consts.FieldAllowedIPv4Addresses: {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Allowed IPv4 addresses for outbound network connectivity in CIDR notation. " +
					"If not set, all IPv4 addresses are allowed.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldAllowedIPv6Addresses: {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Allowed IPv6 addresses for outbound network connectivity in CIDR notation. " +
					"If not set, all IPv6 addresses are allowed.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldAllowedPorts: {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Allowed ports for outbound network connectivity. " +
					"If not set, all ports are allowed.",
				Elem: &schema.Schema{Type: schema.TypeInt},
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
				Deprecated:  "Deprecated in favor of replica_regions for Vault Enterprise 2.1.0+.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldGlobalKmsKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Global KMS key for encryption.",
				Deprecated:  "Deprecated in favor of kms_key_id for Vault Enterprise 2.1.0+.",
			},
			consts.FieldReplicaRegions: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Map of regions to KMS key resource names for replica region encryption. KMS key values are optional.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldKmsKeyID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "KMS key ID for encryption.",
			},
			consts.FieldReplicationLocations: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Replication locations for secrets.",
				Deprecated:  "Deprecated in favor of replica_regions for Vault Enterprise 2.1.0+.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	})
}

func validateGCPSync210Fields(d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if provider.IsAPISupported(meta, provider.VaultVersion210) {
		return nil
	}

	if _, ok := d.GetOk(consts.FieldKmsKeyID); ok {
		return diag.Errorf("kms_key_id is only supported in Vault Enterprise 2.1 and later")
	}

	if _, ok := d.GetOk(consts.FieldReplicaRegions); ok {
		return diag.Errorf("replica_regions is only supported in Vault Enterprise 2.1 and later")
	}

	return nil
}

func gcpSecretsSyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if diags := validateGCPSync210Fields(d, meta); diags != nil {
		return diags
	}

	writeFields := buildGCPSyncWriteFields(meta)
	readFields := buildGCPSyncReadFields(meta)
	// typeSetFields indicates which fields are of TypeSet type and need conversion to List during write
	typeSetFields := map[string]bool{
		consts.FieldAllowedIPv4Addresses: true,
		consts.FieldAllowedIPv6Addresses: true,
		consts.FieldAllowedPorts:         true,
		consts.FieldReplicationLocations: true,
	}
	return syncutil.SyncDestinationCreateUpdateWithOptions(ctx, d, meta, gcpSyncType, writeFields, readFields, typeSetFields)
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
