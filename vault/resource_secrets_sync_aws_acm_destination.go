// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/sdk/helper/template"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	syncutil "github.com/hashicorp/terraform-provider-vault/internal/sync"
)

const (
	awsAcmSyncType = "aws-acm"

	// awsAcmDeliveryModeFullBundle delivers the certificate, CA chain and private key.
	// It is the only delivery mode AWS ACM supports.
	awsAcmDeliveryModeFullBundle = "full_bundle"

	// ACM allows 50 tags per certificate. Vault manages the "hashicorp:vault" and "name" tags.
	awsAcmMaxCustomTags     = 48
	awsAcmMaxTagKeyLength   = 128
	awsAcmMaxTagValueLength = 256
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

// awsAcmSyncClearableFields are removable fields. Vault keeps the stored value when a field
// is omitted from an update, so the empty value must be sent explicitly to clear it.
var awsAcmSyncClearableFields = map[string]bool{
	consts.FieldRoleArn:                 true,
	consts.FieldExternalID:              true,
	consts.FieldCustomTags:              true,
	consts.FieldAllowedIPv4Addresses:    true,
	consts.FieldAllowedIPv6Addresses:    true,
	consts.FieldAllowedPorts:            true,
	consts.FieldDisableStrictNetworking: true,
}

func awsAcmSecretsSyncDestinationResource() *schema.Resource {
	r := &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(awsAcmSecretsSyncDestinationCreateUpdate, provider.VaultVersion230),
		ReadContext:   provider.ReadContextWrapper(awsAcmSecretsSyncDestinationRead),
		UpdateContext: provider.UpdateContextWrapper(awsAcmSecretsSyncDestinationCreateUpdate, provider.VaultVersion230),
		DeleteContext: awsAcmSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validateAwsAcmWIFConfig,
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
				Type:     schema.TypeString,
				Optional: true,
				// Computed because Vault falls back to AWS_REGION and returns the effective region.
				Computed:    true,
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
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				ValidateFunc: validateAwsAcmCertificateNameTemplate,
				Description: "Template evaluated when a certificate is issued to generate the value of the " +
					"'name' tag applied to the certificate imported into ACM.",
			},
			consts.FieldCustomTags: {
				Type:             schema.TypeMap,
				Optional:         true,
				Description:      "Custom tags to set on the certificates imported into AWS ACM.",
				Elem:             &schema.Schema{Type: schema.TypeString},
				ValidateDiagFunc: validateAwsAcmCustomTags,
			},
		},
	}

	provider.MustAddSchema(r, awsAcmWIFSchema())
	provider.MustAddSchema(r, awsAcmNetworkingSchema())

	return r
}

// awsAcmWIFSchema returns the workload identity federation fields. They are defined
// here rather than shared, so that other sync destinations are not affected.
func awsAcmWIFSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
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
			Type:         schema.TypeInt,
			Optional:     true,
			Computed:     true,
			Description:  "The TTL of generated tokens.",
			ValidateFunc: validation.IntAtLeast(1),
		},
	}
}

// awsAcmNetworkingSchema returns the outbound networking fields.
func awsAcmNetworkingSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
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
	}
}

func awsAcmSecretsSyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	name := d.Get(consts.FieldName).(string)
	path := syncutil.SecretsSyncDestinationPath(name, awsAcmSyncType)

	// Vault keeps the stored value of a field that is omitted from an update, and the
	// shared sync helpers never send empty values, so the payload is built here to be able
	// to clear removed fields.
	data := map[string]interface{}{}
	for _, k := range awsAcmSyncWriteFields {
		if v, ok := d.GetOk(k); ok {
			if set, isSet := v.(*schema.Set); isSet {
				data[k] = set.List()
			} else {
				data[k] = v
			}
		} else if awsAcmSyncClearableFields[k] && !d.IsNewResource() && d.HasChange(k) {
			data[k] = awsAcmClearedValue(d.Get(k))
		}

		// write-only values are only sent on create or when their version changes
		switch k {
		case consts.FieldIdentityTokenAudience:
			awsAcmSetWriteOnly(d, data, k, consts.FieldIdentityTokenAudienceWO, consts.FieldIdentityTokenAudienceWOVersion)
		case consts.FieldIdentityTokenKey:
			awsAcmSetWriteOnly(d, data, k, consts.FieldIdentityTokenKeyWO, consts.FieldIdentityTokenKeyWOVersion)
		}
	}

	if _, err := client.Logical().WriteWithContext(ctx, path, data); err != nil {
		return diag.Errorf("error writing sync destination data to %q: %s", path, err)
	}

	if d.IsNewResource() {
		d.SetId(name)
	}

	return awsAcmSecretsSyncDestinationRead(ctx, d, meta)
}

func awsAcmSetWriteOnly(d *schema.ResourceData, data map[string]interface{}, key, woField, versionField string) {
	if !d.IsNewResource() && !d.HasChange(versionField) {
		return
	}
	v, diags := d.GetRawConfigAt(cty.GetAttrPath(woField))
	if diags.HasError() || v.IsNull() || !v.IsKnown() {
		return
	}
	data[key] = v.AsString()
}

// awsAcmClearedValue returns the empty value of the same type as v.
func awsAcmClearedValue(v interface{}) interface{} {
	switch v.(type) {
	case *schema.Set:
		return []interface{}{}
	case map[string]interface{}:
		return map[string]interface{}{}
	case bool:
		return false
	default:
		return ""
	}
}

func awsAcmSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationRead(ctx, d, meta, awsAcmSyncType, awsAcmSyncReadFields, nil)
}

func awsAcmSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, awsAcmSyncType)
}

// validateAwsAcmCertificateNameTemplate checks that the template parses. Vault only
// validates this on create and reports render errors when a certificate is synced.
func validateAwsAcmCertificateNameTemplate(i interface{}, k string) ([]string, []error) {
	v, ok := i.(string)
	if !ok {
		return nil, []error{fmt.Errorf("expected type of %q to be string", k)}
	}
	if _, err := template.NewTemplate(template.Template(v)); err != nil {
		return nil, []error{fmt.Errorf("%q is not a valid template: %w", k, err)}
	}
	return nil, nil
}

// validateAwsAcmCustomTags enforces the ACM tag limits at plan time.
func validateAwsAcmCustomTags(i interface{}, path cty.Path) diag.Diagnostics {
	tags, ok := i.(map[string]interface{})
	if !ok {
		return diag.Diagnostics{{Severity: diag.Error, Summary: "expected a map of strings", AttributePath: path}}
	}

	var diags diag.Diagnostics
	if len(tags) > awsAcmMaxCustomTags {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "too many custom tags",
			Detail: fmt.Sprintf("at most %d custom tags are allowed, got %d: ACM allows 50 tags per "+
				"certificate and Vault reserves 2", awsAcmMaxCustomTags, len(tags)),
			AttributePath: path,
		})
	}
	for key, val := range tags {
		value, _ := val.(string)
		if len(key) > awsAcmMaxTagKeyLength {
			diags = append(diags, diag.Diagnostic{
				Severity:      diag.Error,
				Summary:       "custom tag key too long",
				Detail:        fmt.Sprintf("tag key %q must be at most %d characters long", key, awsAcmMaxTagKeyLength),
				AttributePath: append(path.Copy(), cty.IndexStep{Key: cty.StringVal(key)}),
			})
		}
		if len(value) > awsAcmMaxTagValueLength {
			diags = append(diags, diag.Diagnostic{
				Severity:      diag.Error,
				Summary:       "custom tag value too long",
				Detail:        fmt.Sprintf("the value of tag %q must be at most %d characters long", key, awsAcmMaxTagValueLength),
				AttributePath: append(path.Copy(), cty.IndexStep{Key: cty.StringVal(key)}),
			})
		}
	}
	return diags
}

// validateAwsAcmWIFConfig enforces constraints that Vault would otherwise only report on write,
// or silently ignore: write-only values are only sent when their version counter changes, and
// workload identity federation requires a role to assume.
func validateAwsAcmWIFConfig(_ context.Context, req schema.ValidateResourceConfigFuncRequest, resp *schema.ValidateResourceConfigFuncResponse) {
	cfg := req.RawConfig
	if cfg.IsNull() || !cfg.IsKnown() {
		return
	}

	attr := func(name string) cty.Value { return cfg.GetAttr(name) }
	isSet := func(v cty.Value) bool { return !v.IsKnown() || !v.IsNull() }
	addErr := func(name, summary, detail string) {
		resp.Diagnostics = append(resp.Diagnostics, diag.Diagnostic{
			Severity:      diag.Error,
			Summary:       summary,
			Detail:        detail,
			AttributePath: cty.GetAttrPath(name),
		})
	}

	audience := attr(consts.FieldIdentityTokenAudienceWO)
	if isSet(audience) {
		if roleArn := attr(consts.FieldRoleArn); roleArn.IsKnown() &&
			(roleArn.IsNull() || roleArn.AsString() == "") {
			addErr(consts.FieldRoleArn, "Missing required argument",
				fmt.Sprintf("%q is required when %q is set", consts.FieldRoleArn, consts.FieldIdentityTokenAudienceWO))
		}
		if !isSet(attr(consts.FieldIdentityTokenAudienceWOVersion)) {
			addErr(consts.FieldIdentityTokenAudienceWOVersion, "Missing required argument",
				fmt.Sprintf("%q is required when %q is set, because changes to a write-only value are only "+
					"applied when its version changes", consts.FieldIdentityTokenAudienceWOVersion,
					consts.FieldIdentityTokenAudienceWO))
		}
	}

	if isSet(attr(consts.FieldIdentityTokenKeyWO)) && !isSet(attr(consts.FieldIdentityTokenKeyWOVersion)) {
		addErr(consts.FieldIdentityTokenKeyWOVersion, "Missing required argument",
			fmt.Sprintf("%q is required when %q is set, because changes to a write-only value are only "+
				"applied when its version changes", consts.FieldIdentityTokenKeyWOVersion,
				consts.FieldIdentityTokenKeyWO))
	}
}
