// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	syncutil "github.com/hashicorp/terraform-provider-vault/internal/sync"
)

const (
	awsAcmSyncType = "aws-acm"

	// awsAcmDeliveryModeFullBundle delivers the certificate, CA chain and private key.
	// It is the only delivery mode AWS ACM supports.
	awsAcmDeliveryModeFullBundle = "full_bundle"
)

var awsAcmSyncWriteFields = []string{
	fieldAccessKeyID,
	fieldSecretAccessKey,
	consts.FieldRegion,
	consts.FieldRoleArn,
	consts.FieldExternalID,
	consts.FieldDeliveryMode,
	consts.FieldCertificateNameTemplate,
	consts.FieldCustomTags,
	consts.FieldAllowedIPv4Addresses,
	consts.FieldAllowedIPv6Addresses,
	consts.FieldAllowedPorts,
	consts.FieldDisableStrictNetworking,
	consts.FieldIdentityTokenAudience,
	consts.FieldIdentityTokenTTL,
	consts.FieldIdentityTokenKey,
}

// awsAcmSyncReadFields excludes credentials and identity token key/audience,
// because Vault returns them masked.
var awsAcmSyncReadFields = []string{
	consts.FieldRegion,
	consts.FieldRoleArn,
	consts.FieldExternalID,
	consts.FieldDeliveryMode,
	consts.FieldCertificateNameTemplate,
	consts.FieldCustomTags,
	consts.FieldAllowedIPv4Addresses,
	consts.FieldAllowedIPv6Addresses,
	consts.FieldAllowedPorts,
	consts.FieldDisableStrictNetworking,
	consts.FieldIdentityTokenTTL,
}

var awsAcmSyncTypeSetFields = map[string]bool{
	consts.FieldAllowedIPv4Addresses: true,
	consts.FieldAllowedIPv6Addresses: true,
	consts.FieldAllowedPorts:         true,
}

func awsAcmSecretsSyncDestinationResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(awsAcmSecretsSyncDestinationCreateUpdate, provider.VaultVersion230),
		ReadContext:   provider.ReadContextWrapper(awsAcmSecretsSyncDestinationRead),
		UpdateContext: awsAcmSecretsSyncDestinationCreateUpdate,
		DeleteContext: awsAcmSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the AWS ACM destination.",
				ForceNew:    true,
			},
			consts.FieldType: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Type of secrets destination.",
			},
			fieldAccessKeyID: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "Access key id to authenticate against AWS Certificate Manager.",
				ConflictsWith: []string{consts.FieldIdentityTokenAudienceWO},
			},
			fieldSecretAccessKey: {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				Description:   "Secret access key to authenticate against AWS Certificate Manager.",
				ConflictsWith: []string{consts.FieldIdentityTokenAudienceWO},
			},
			consts.FieldRegion: {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Region where certificates are imported into AWS Certificate Manager.",
			},
			consts.FieldRoleArn: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a role to assume when connecting to AWS.",
			},
			consts.FieldExternalID: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "Extra protection that must match the trust policy granting access to the AWS IAM role ARN.",
				ConflictsWith: []string{consts.FieldIdentityTokenAudienceWO},
			},
			consts.FieldDeliveryMode: {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Controls which parts of a PKI certificate are synced to AWS ACM. Only 'full_bundle' is supported.",
				ValidateFunc: validation.StringInSlice([]string{awsAcmDeliveryModeFullBundle}, false),
			},
			consts.FieldCertificateNameTemplate: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "Template evaluated when a certificate is issued to generate the value of the " +
					"'name' tag applied to the certificate imported into ACM.",
			},
			consts.FieldCustomTags: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Custom tags to set on the certificates imported into AWS ACM.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldIdentityTokenKeyWO: {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Sensitive:   true,
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
			consts.FieldAllowedIPv4Addresses: {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Allowed IPv4 addresses for outbound connections from Vault to AWS ACM. " +
					"Can also be set via an IP address range using CIDR notation.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldAllowedIPv6Addresses: {
				Type:     schema.TypeSet,
				Optional: true,
				Description: "Allowed IPv6 addresses for outbound connections from Vault to AWS ACM. " +
					"Can also be set via an IP address range using CIDR notation.",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldAllowedPorts: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Allowed ports for outbound connections from Vault to AWS ACM.",
				Elem:        &schema.Schema{Type: schema.TypeInt},
			},
			consts.FieldDisableStrictNetworking: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
				Description: "Disable strict networking mode. When set to true, " +
					"Vault will not enforce allowed IP addresses and ports.",
			},
		},
	}
}

func awsAcmSecretsSyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationCreateUpdateWithOptions(ctx, d, meta, awsAcmSyncType,
		awsAcmSyncWriteFields, awsAcmSyncReadFields, awsAcmSyncTypeSetFields)
}

func awsAcmSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationRead(ctx, d, meta, awsAcmSyncType, awsAcmSyncReadFields, nil)
}

func awsAcmSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, awsAcmSyncType)
}
