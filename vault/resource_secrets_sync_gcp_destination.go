// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"

	"github.com/hashicorp/go-cty/cty"
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
			consts.FieldIdentityTokenKey: {
				Type:        schema.TypeString,
				WriteOnly:   true,
				Optional:    true,
				Description: "The key to use for signing identity tokens. This is a write-only field and will not be read back from Vault.",
			},
			consts.FieldIdentityTokenKeyWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "A version counter for the write-only identity_token_key field. Incrementing this value will trigger an update.",
				RequiredWith: []string{consts.FieldIdentityTokenKey},
			},
			consts.FieldIdentityTokenAudience: {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "The audience claim value for identity tokens. This is a write-only field and will not be read back from Vault.",
			},
			consts.FieldIdentityTokenAudienceWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "A version counter for the write-only identity_token_audience field. Incrementing this value will trigger an update.",
				RequiredWith: []string{consts.FieldIdentityTokenAudience},
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
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldGlobalKmsKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Global KMS key for encryption.",
			},
			consts.FieldReplicationLocations: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Replication locations for secrets.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	})
}

func gcpSecretsSyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	path := syncutil.SecretsSyncDestinationPath(name, gcpSyncType)

	writeFields := buildGCPSyncWriteFields(meta)
	// typeSetFields indicates which fields are of TypeSet type and need conversion to List during write
	typeSetFields := map[string]bool{
		consts.FieldAllowedIPv4Addresses: true,
		consts.FieldAllowedIPv6Addresses: true,
		consts.FieldAllowedPorts:         true,
		consts.FieldReplicationLocations: true,
	}

	data := map[string]interface{}{}

	// Build data map from write fields
	for _, k := range writeFields {
		// Skip write-only fields - they'll be handled separately below
		if k == consts.FieldIdentityTokenKey || k == consts.FieldIdentityTokenAudience {
			continue
		}

		if v, ok := d.GetOk(k); ok {
			// Convert TypeSet to List for JSON serialization if needed
			if typeSetFields[k] {
				if set, ok := v.(*schema.Set); ok {
					data[k] = set.List()
					continue
				}
			}
			data[k] = v
		}
	}

	// Handle write-only fields using GetRawConfigAt for Vault 2.0.0+
	if provider.IsAPISupported(meta, provider.VaultVersion200) {
		// Handle identity_token_key (write-only)
		if identityTokenKeyRaw, _ := d.GetRawConfigAt(cty.GetAttrPath(consts.FieldIdentityTokenKey)); !identityTokenKeyRaw.IsNull() {
			data[consts.FieldIdentityTokenKey] = identityTokenKeyRaw.AsString()
		}

		// Handle identity_token_audience (write-only)
		if identityTokenAudienceRaw, _ := d.GetRawConfigAt(cty.GetAttrPath(consts.FieldIdentityTokenAudience)); !identityTokenAudienceRaw.IsNull() {
			data[consts.FieldIdentityTokenAudience] = identityTokenAudienceRaw.AsString()
		}
	}

	log.Printf("[DEBUG] Writing sync destination data to %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error writing sync destination data %q to %q: %s", data, path, err)
	}
	log.Printf("[DEBUG] Wrote sync destination data to %q", path)

	if d.IsNewResource() {
		d.SetId(name)
	}

	return gcpSecretsSyncDestinationRead(ctx, d, meta)
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
