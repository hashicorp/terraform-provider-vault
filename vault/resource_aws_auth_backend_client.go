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
	backend := d.Get("backend").(string)
	ec2Endpoint := d.Get("ec2_endpoint").(string)
	iamEndpoint := d.Get("iam_endpoint").(string)
	stsEndpoint := d.Get("sts_endpoint").(string)
	stsRegion := d.Get("sts_region").(string)
	stsRegionFromClient := d.Get("use_sts_region_from_client").(bool)

	iamServerIDHeaderValue := d.Get("iam_server_id_header_value").(string)

	path := awsAuthBackendClientPath(backend)

	data := map[string]interface{}{
		"endpoint":                   ec2Endpoint,
		"iam_endpoint":               iamEndpoint,
		"sts_endpoint":               stsEndpoint,
		"sts_region":                 stsRegion,
		"iam_server_id_header_value": iamServerIDHeaderValue,
	}

	useAPIVer117 := provider.IsAPISupported(meta, provider.VaultVersion117)
	if useAPIVer117 {
		if v, ok := d.GetOk(consts.FieldIdentityTokenAudience); ok && v != "" {
			data[consts.FieldIdentityTokenAudience] = v.(string)
		}
		if v, ok := d.GetOk(consts.FieldRoleArn); ok && v != "" {
			data[consts.FieldRoleArn] = v.(string)
		}
		if v, ok := d.GetOk(consts.FieldIdentityTokenTTL); ok && v != 0 {
			data[consts.FieldIdentityTokenTTL] = v.(int)
		}
	}

	if d.HasChange("access_key") || d.HasChange("secret_key") {
		log.Printf("[DEBUG] Updating AWS credentials at %q", path)
		data["access_key"] = d.Get("access_key").(string)
		data["secret_key"] = d.Get("secret_key").(string)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		data[useSTSRegionFromClient] = stsRegionFromClient
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

	d.Set("access_key", secret.Data["access_key"])
	d.Set("ec2_endpoint", secret.Data["endpoint"])
	d.Set("iam_endpoint", secret.Data["iam_endpoint"])
	d.Set("sts_endpoint", secret.Data["sts_endpoint"])
	d.Set("sts_region", secret.Data["sts_region"])
	d.Set("iam_server_id_header_value", secret.Data["iam_server_id_header_value"])
	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		d.Set(useSTSRegionFromClient, secret.Data[useSTSRegionFromClient])
	}
	useAPIVer117 := provider.IsAPISupported(meta, provider.VaultVersion117)
	if useAPIVer117 {
		if err := d.Set(consts.FieldIdentityTokenAudience, secret.Data[consts.FieldIdentityTokenAudience]); err != nil {
			return diag.Errorf("error reading AWS Auth Backend %s: %v", consts.FieldIdentityTokenAudience, err)
		}
		if err := d.Set(consts.FieldRoleArn, secret.Data[consts.FieldRoleArn]); err != nil {
			return diag.Errorf("error reading AWS Auth Backend %s: %v", consts.FieldRoleArn, err)
		}
		if err := d.Set(consts.FieldIdentityTokenTTL, secret.Data[consts.FieldIdentityTokenTTL]); err != nil {
			return diag.Errorf("error reading AWS Auth Backend %s: %v", consts.FieldIdentityTokenTTL, err)
		}
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
