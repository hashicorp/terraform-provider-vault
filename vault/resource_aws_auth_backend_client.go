// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"
	"net/textproto"
	"regexp"
	"strings"

	automatedrotationutil "github.com/hashicorp/terraform-provider-vault/internal/rotation"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	useSTSRegionFromClient = "use_sts_region_from_client"
)

func awsAuthBackendClientResource() *schema.Resource {
	r := &schema.Resource{
		CreateContext: awsAuthBackendWrite,
		ReadContext:   provider.ReadContextWrapper(awsAuthBackendRead),
		UpdateContext: awsAuthBackendWrite,
		DeleteContext: awsAuthBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "aws",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			consts.FieldAccessKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS Access key with permissions to query AWS APIs.",
				Sensitive:   true,
			},
			consts.FieldSecretKey: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "AWS Secret key with permissions to query AWS APIs.",
				Sensitive:     true,
				ConflictsWith: []string{consts.FieldSecretKeyWO},
			},
			consts.FieldSecretKeyWO: {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				WriteOnly:     true,
				Description:   "Write-only AWS Secret key with permissions to query AWS APIs. This field is recommended over secret_key for enhanced security.",
				ConflictsWith: []string{consts.FieldSecretKey},
			},
			consts.FieldSecretKeyWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Version counter for write-only secret_key field. Increment this value to force update of the secret.",
				RequiredWith: []string{consts.FieldSecretKeyWO},
			},
			consts.FieldEC2Endpoint: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL to override the default generated endpoint for making AWS EC2 API calls.",
			},
			consts.FieldIAMEndpoint: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL to override the default generated endpoint for making AWS IAM API calls.",
			},
			consts.FieldSTSEndpoint: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL to override the default generated endpoint for making AWS STS API calls.",
			},
			consts.FieldSTSRegion: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Region to override the default region for making AWS STS API calls.",
			},
			useSTSRegionFromClient: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "If set, will override sts_region and use the region from the client request's header",
			},
			consts.FieldAllowedSTSHeaderValues: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of additional headers that are allowed to be in STS request headers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
					StateFunc: func(v interface{}) string {
						original := strings.TrimSpace(v.(string))
						// Canonicalize header names for consistent state storage
						canonical := textproto.CanonicalMIMEHeaderKey(original)
						return canonical
					},
				},
			},
			consts.FieldIAMServerIDHeaderValue: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value to require in the X-Vault-AWS-IAM-Server-ID header as part of GetCallerIdentity requests that are used in the iam auth method.",
			},
			consts.FieldRoleArn: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Role ARN to assume for plugin identity token federation.",
			},
			consts.FieldIdentityTokenAudience: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The audience claim value.",
			},
			consts.FieldIdentityTokenTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The TTL of generated identity tokens in seconds.",
			},
			consts.FieldMaxRetries: {
				Type:        schema.TypeInt,
				Default:     -1,
				Optional:    true,
				Description: "Number of max retries the client should use for recoverable errors.",
			},
		},
	}

	// Add common automated root rotation schema to the resource
	provider.MustAddSchema(r, provider.GetAutomatedRootRotationSchema())

	return r
}

func awsAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	// if backend comes from the config, it won't have the StateFunc
	// applied yet, so we need to apply it again.
	backend := d.Get(consts.FieldBackend).(string)
	ec2Endpoint := d.Get(consts.FieldEC2Endpoint).(string)
	iamEndpoint := d.Get(consts.FieldIAMEndpoint).(string)
	stsEndpoint := d.Get(consts.FieldSTSEndpoint).(string)
	stsRegion := d.Get(consts.FieldSTSRegion).(string)
	stsRegionFromClient := d.Get(useSTSRegionFromClient).(bool)
	allowedSTSHeaderValuesSet := d.Get(consts.FieldAllowedSTSHeaderValues).(*schema.Set)
	var allowedSTSHeaderValuesList []string
	if allowedSTSHeaderValuesSet.Len() > 0 {
		// Convert TypeSet to slice for Vault API
		// Need explicit deduplication because TypeSet may not handle StateFunc canonicalization properly
		allowedSTSHeaderValuesList = make([]string, 0, allowedSTSHeaderValuesSet.Len())
		seenHeaders := make(map[string]bool) // Track duplicates after canonicalization

		for _, v := range allowedSTSHeaderValuesSet.List() {
			header := strings.TrimSpace(v.(string))
			canonical := textproto.CanonicalMIMEHeaderKey(header)

			// Only add if we haven't seen this canonical form before
			if !seenHeaders[canonical] {
				allowedSTSHeaderValuesList = append(allowedSTSHeaderValuesList, canonical)
				seenHeaders[canonical] = true
			}
		}
	}
	identityTokenAud := d.Get(consts.FieldIdentityTokenAudience).(string)
	roleArn := d.Get(consts.FieldRoleArn).(string)
	identityTokenTTL := d.Get(consts.FieldIdentityTokenTTL).(int)
	maxRetries := d.Get(consts.FieldMaxRetries).(int)
	iamServerIDHeaderValue := d.Get(consts.FieldIAMServerIDHeaderValue).(string)

	path := awsAuthBackendClientPath(backend)

	data := map[string]interface{}{
		"endpoint":                         ec2Endpoint,
		consts.FieldIAMEndpoint:            iamEndpoint,
		consts.FieldSTSEndpoint:            stsEndpoint,
		consts.FieldSTSRegion:              stsRegion,
		consts.FieldAllowedSTSHeaderValues: allowedSTSHeaderValuesList,
		consts.FieldIAMServerIDHeaderValue: iamServerIDHeaderValue,
		consts.FieldMaxRetries:             maxRetries,
	}

	if d.HasChanges(consts.FieldAccessKey, consts.FieldSecretKey, consts.FieldSecretKeyWOVersion) {
		log.Printf("[DEBUG] Updating AWS credentials at %q", path)

		// Always set access_key when credentials change (including empty to clear)
		data[consts.FieldAccessKey] = d.Get(consts.FieldAccessKey).(string)

		// Get secret_key from either legacy or write-only field
		var secretKey string
		if v, ok := d.GetOk(consts.FieldSecretKey); ok {
			secretKey = v.(string)
		} else if d.IsNewResource() || d.HasChange(consts.FieldSecretKeyWOVersion) {
			p := cty.GetAttrPath(consts.FieldSecretKeyWO)
			woVal, _ := d.GetRawConfigAt(p)
			if !woVal.IsNull() {
				secretKey = woVal.AsString()
			}
		}

		// Only set secret_key if it has a value (don't send empty secret_key)
		if secretKey != "" {
			data[consts.FieldSecretKey] = secretKey
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		data[useSTSRegionFromClient] = stsRegionFromClient
	}

	if provider.IsAPISupported(meta, provider.VaultVersion117) && provider.IsEnterpriseSupported(meta) {
		data[consts.FieldIdentityTokenAudience] = identityTokenAud
		data[consts.FieldRoleArn] = roleArn
		data[consts.FieldIdentityTokenTTL] = identityTokenTTL
	}

	if provider.IsAPISupported(meta, provider.VaultVersion119) && provider.IsEnterpriseSupported(meta) {
		// parse automated root rotation fields if Enterprise 1.19 server
		automatedrotationutil.ParseAutomatedRotationFields(d, data)
	}

	// sts_endpoint and sts_region are required to be set together
	if (stsEndpoint == "") != (stsRegion == "") {
		return diag.Errorf("both sts_endpoint and sts_region need to be set")
	}

	log.Printf("[DEBUG] Writing AWS auth backend client config to %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error writing to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote AWS auth backend client config to %q", path)

	d.SetId(path)

	return awsAuthBackendRead(ctx, d, meta)
}

func awsAuthBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	log.Printf("[DEBUG] Reading AWS auth backend client config")
	secret, err := client.Logical().ReadWithContext(ctx, d.Id())
	if err != nil {
		return diag.Errorf("error reading AWS auth backend client config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Read AWS auth backend client config")

	if secret == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", d.Id())
		d.SetId("")
		return nil
	}

	// set the backend to the original passed path (without config/client at the end)
	re := regexp.MustCompile(`^auth/(.*)/config/client$`)
	if !re.MatchString(d.Id()) {
		return diag.Errorf("`config/client` has not been appended to the ID (%s)", d.Id())
	}
	d.Set("backend", re.FindStringSubmatch(d.Id())[1])

	if err := d.Set(consts.FieldEC2Endpoint, secret.Data["endpoint"]); err != nil {
		return diag.FromErr(err)
	}
	fields := []string{
		consts.FieldAccessKey,
		consts.FieldIAMEndpoint,
		consts.FieldSTSEndpoint,
		consts.FieldSTSRegion,
		consts.FieldIAMServerIDHeaderValue,
		consts.FieldMaxRetries,
	}
	for _, k := range fields {
		if v, ok := secret.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	// Handle allowed_sts_header_values conversion from Vault's slice to set
	var headers []string
	if headersInterface, ok := secret.Data[consts.FieldAllowedSTSHeaderValues]; ok {
		// Convert interface{} slice to string slice
		if headersList, ok := headersInterface.([]interface{}); ok {
			headers = make([]string, 0, len(headersList))
			for _, header := range headersList {
				if headerStr, ok := header.(string); ok {
					headers = append(headers, strings.TrimSpace(headerStr))
				}
			}
		}
	}
	if err := d.Set(consts.FieldAllowedSTSHeaderValues, headers); err != nil {
		return diag.FromErr(err)
	}
	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		if err := d.Set(useSTSRegionFromClient, secret.Data[useSTSRegionFromClient]); err != nil {
			return diag.FromErr(err)
		}
	}
	if provider.IsAPISupported(meta, provider.VaultVersion117) && provider.IsEnterpriseSupported(meta) {
		wifFields := []string{
			consts.FieldIdentityTokenAudience,
			consts.FieldRoleArn,
			consts.FieldIdentityTokenTTL,
		}
		for _, k := range wifFields {
			if v, ok := secret.Data[k]; ok {
				if err := d.Set(k, v); err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion119) && provider.IsEnterpriseSupported(meta) {
		if err := automatedrotationutil.PopulateAutomatedRotationFields(d, secret, d.Id()); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func awsAuthBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	log.Printf("[DEBUG] Deleting AWS auth backend client config from %q", d.Id())
	_, err := client.Logical().DeleteWithContext(ctx, d.Id())
	if err != nil {
		return diag.Errorf("error deleting AWS auth backend client config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Deleted AWS auth backend client config from %q", d.Id())

	return nil
}

func awsAuthBackendClientPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config/client"
}
