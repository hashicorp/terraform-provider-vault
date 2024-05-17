// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	useSTSRegionFromClient = "use_sts_region_from_client"
)

func awsAuthBackendClientResource() *schema.Resource {
	return &schema.Resource{
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
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS Secret key with permissions to query AWS APIs.",
				Sensitive:   true,
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
		},
	}
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

	identityTokenAud := d.Get(consts.FieldIdentityTokenAudience).(string)
	roleArn := d.Get(consts.FieldRoleArn).(string)
	identityTokenTTL := d.Get(consts.FieldIdentityTokenTTL).(int)

	iamServerIDHeaderValue := d.Get(consts.FieldIAMServerIDHeaderValue).(string)

	path := awsAuthBackendClientPath(backend)

	data := map[string]interface{}{
		"endpoint":                         ec2Endpoint,
		consts.FieldIAMEndpoint:            iamEndpoint,
		consts.FieldSTSEndpoint:            stsEndpoint,
		consts.FieldSTSRegion:              stsRegion,
		consts.FieldIAMServerIDHeaderValue: iamServerIDHeaderValue,
	}

	if d.HasChange(consts.FieldAccessKey) || d.HasChange(consts.FieldSecretKey) {
		log.Printf("[DEBUG] Updating AWS credentials at %q", path)
		data[consts.FieldAccessKey] = d.Get(consts.FieldAccessKey).(string)
		data[consts.FieldSecretKey] = d.Get(consts.FieldSecretKey).(string)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		data[useSTSRegionFromClient] = stsRegionFromClient
	}

	if provider.IsAPISupported(meta, provider.VaultVersion117) {
		data[consts.FieldIdentityTokenAudience] = identityTokenAud
		data[consts.FieldRoleArn] = roleArn
		data[consts.FieldIdentityTokenTTL] = identityTokenTTL
	}

	// sts_endpoint and sts_region are required to be set together
	if (stsEndpoint == "") != (stsRegion == "") {
		return diag.Errorf("both sts_endpoint and sts_region need to be set")
	}

	log.Printf("[DEBUG] Writing AWS auth backend client config to %q", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error writing to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote AWS auth backend client config to %q", path)

	d.SetId(path)

	return awsAuthBackendRead(ctx, d, meta)
}

func awsAuthBackendRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	log.Printf("[DEBUG] Reading AWS auth backend client config")
	secret, err := client.Logical().Read(d.Id())
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

	d.Set(consts.FieldAccessKey, secret.Data[consts.FieldAccessKey])
	d.Set(consts.FieldEC2Endpoint, secret.Data["endpoint"])
	d.Set(consts.FieldIAMEndpoint, secret.Data["iam_endpoint"])
	d.Set(consts.FieldSTSEndpoint, secret.Data["sts_endpoint"])
	d.Set(consts.FieldSTSRegion, secret.Data["sts_region"])
	d.Set(consts.FieldIAMServerIDHeaderValue, secret.Data[consts.FieldIAMServerIDHeaderValue])
	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		d.Set(useSTSRegionFromClient, secret.Data[useSTSRegionFromClient])
	}
	if provider.IsAPISupported(meta, provider.VaultVersion117) {
		d.Set(consts.FieldIdentityTokenAudience, secret.Data[consts.FieldIdentityTokenAudience])
		d.Set(consts.FieldRoleArn, secret.Data[consts.FieldRoleArn])
		d.Set(consts.FieldIdentityTokenTTL, secret.Data[consts.FieldIdentityTokenTTL])
	}

	return nil
}

func awsAuthBackendDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	log.Printf("[DEBUG] Deleting AWS auth backend client config from %q", d.Id())
	_, err := client.Logical().Delete(d.Id())
	if err != nil {
		return diag.Errorf("error deleting AWS auth backend client config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Deleted AWS auth backend client config from %q", d.Id())

	return nil
}

func awsAuthBackendClientPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config/client"
}
