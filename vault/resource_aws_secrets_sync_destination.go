// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldAccessKeyID     = "access_key_id"
	fieldSecretAccessKey = "secret_access_key"
)

var awsSyncDestinationFields = []string{
	fieldAccessKeyID,
	fieldSecretAccessKey,
	consts.FieldAWSRegion,
}

func awsSecretsSyncDestinationResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(awsSecretsSyncDestinationWrite, provider.VaultVersion115),
		ReadContext:   provider.ReadContextWrapper(awsSecretsSyncDestinationRead),
		DeleteContext: awsSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the AWS destination.",
				ForceNew:    true,
			},
			fieldAccessKeyID: {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Access key id to authenticate against the AWS secrets manager.",
				ForceNew:    true,
			},
			fieldSecretAccessKey: {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Description: "Secret access key to authenticate against the AWS secrets " +
					"manager.",
				ForceNew: true,
			},
			consts.FieldRegion: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Region where to manage the secrets manager entries.",
				ForceNew:    true,
			},
		},
	}
}

func awsSecretsSyncDestinationWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	path := awsSecretsSyncDestinationPath(name)

	data := map[string]interface{}{}

	for _, k := range awsSyncDestinationFields {
		data[k] = d.Get(k)
	}

	log.Printf("[DEBUG] Writing AWS sync destination to %q", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error enabling AWS sync destination %q: %s", path, err)
	}
	log.Printf("[DEBUG] Enabled AWS sync destination %q", path)

	d.SetId(name)

	return awsSecretsSyncDestinationRead(ctx, d, meta)
}

func awsSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	name := d.Id()
	path := awsSecretsSyncDestinationPath(name)

	log.Printf("[DEBUG] Reading AWS sync destination")
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading AWS sync destination from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read AWS sync destination")

	if resp == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range awsSyncDestinationFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error setting state key %q: err=%s", k, err)
			}
		}
	}

	// set sensitive fields that will not be returned from Vault

	return nil
}

func awsSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// sync destinations can not be deleted
	return nil
}

func awsSecretsSyncDestinationPath(name string) string {
	return "sys/sync/destinations/aws-sm/" + name
}
