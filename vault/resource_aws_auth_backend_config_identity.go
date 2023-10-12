// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var awsAuthBackendConfigIdentityBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/config/identity$")

func awsAuthBackendConfigIdentityResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: awsAuthBackendConfigIdentityWrite,
		UpdateContext: awsAuthBackendConfigIdentityWrite,
		ReadContext:   awsAuthBackendConfigIdentityRead,
		DeleteContext: awsAuthBackendConfigIdentityDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldIAMAlias: {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "role_id",
				Description:  "How to generate the identity alias when using the iam auth method.",
				ValidateFunc: validation.StringInSlice([]string{"role_id", "unique_id", "full_arn"}, false),
			},
			consts.FieldIAMMetadata: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "The metadata to include on the token returned by the login endpoint.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldEC2Alias: {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Configures how to generate the identity alias when using the ec2 auth method.",
				Default:      "role_id",
				ValidateFunc: validation.StringInSlice([]string{"role_id", "instance_id", "image_id"}, false),
			},
			consts.FieldEC2Metadata: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "The metadata to include on the token returned by the login endpoint.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
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
		},
	}
}

func awsAuthBackendConfigIdentityWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)

	var iamMetadata, ec2Metadata []string
	if iamMetadataConfig, ok := d.GetOk(consts.FieldIAMMetadata); ok {
		iamMetadata = util.TerraformSetToStringArray(iamMetadataConfig)
	}

	if ec2MetadataConfig, ok := d.GetOk(consts.FieldEC2Metadata); ok {
		ec2Metadata = util.TerraformSetToStringArray(ec2MetadataConfig)
	}

	data := map[string]interface{}{
		consts.FieldIAMMetadata: iamMetadata,
		consts.FieldEC2Metadata: ec2Metadata,
	}

	fields := []string{
		consts.FieldIAMAlias,
		consts.FieldEC2Alias,
	}
	for _, k := range fields {
		data[k] = d.Get(k)
	}

	path := awsAuthBackendConfigIdentityPath(backend)

	log.Printf("[DEBUG] Writing AWS identity config to %q", path)
	_, err = client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error configuring AWS auth identity config %q: %s", path, err)
	}
	d.SetId(path)

	log.Printf("[DEBUG] Wrote AWS identity config to %q", path)

	return awsAuthBackendConfigIdentityRead(ctx, d, meta)
}

func awsAuthBackendConfigIdentityRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()

	backend, err := awsAuthBackendConfigIdentityBackendFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for AWS auth identity config:  %s", path, err)
	}

	log.Printf("[DEBUG] Reading identity config %q from AWS auth backend", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading AWS auth backend identity config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read identity config %q from AWS auth backend", path)
	if resp == nil {
		log.Printf("[WARN] AWS auth backend identity config %q not found, removing it from state", path)
		d.SetId("")
		return nil
	}

	fields := []string{
		consts.FieldIAMAlias,
		consts.FieldIAMMetadata,
		consts.FieldEC2Alias,
		consts.FieldEC2Metadata,
	}
	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}
	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func awsAuthBackendConfigIdentityDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	log.Printf("[DEBUG] Deleting AWS identity config from state file")
	return nil
}

func awsAuthBackendConfigIdentityPath(backend string) string {
	return "auth/" + strings.Trim(backend, "/") + "/config/identity"
}

func awsAuthBackendConfigIdentityBackendFromPath(path string) (string, error) {
	if !awsAuthBackendConfigIdentityBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := awsAuthBackendConfigIdentityBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
