// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func mfaDuoResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: mfaDuoWrite,
		UpdateContext: mfaDuoWrite,
		DeleteContext: mfaDuoDelete,
		ReadContext:   provider.ReadContextWrapper(mfaDuoRead),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Name of the MFA method.",
				ValidateFunc: provider.ValidateNoTrailingSlash,
			},
			consts.FieldMountAccessor: {
				Type:     schema.TypeString,
				Required: true,
				Description: "The mount to tie this method to for use in automatic mappings. " +
					"The mapping will use the Name field of Aliases associated with this mount as " +
					"the username in the mapping.",
			},
			consts.FieldUsernameFormat: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "A format string for mapping Identity names to MFA method names. " +
					"Values to substitute should be placed in `{{}}`.",
			},
			consts.FieldSecretKey: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Secret key for Duo.",
			},
			consts.FieldIntegrationKey: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Integration key for Duo.",
			},
			consts.FieldAPIHostname: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "API hostname for Duo.",
			},
			consts.FieldPushInfo: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Push information for Duo.",
			},
		},
	}
}

func mfaDuoWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)

	data := map[string]interface{}{}
	mfaDuoUpdateFields(d, data)

	log.Printf("[DEBUG] Writing role %q to MFA Duo auth backend", name)
	d.SetId(name)

	log.Printf("[DEBUG] Creating mfaDuo %s in Vault", name)
	_, err := client.Logical().Write(mfaDuoPath(name), data)
	if err != nil {
		return diag.Errorf("error writing to Vault: %s", err)
	}

	return mfaDuoRead(ctx, d, meta)
}

func mfaDuoDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)

	log.Printf("[DEBUG] Deleting mfaDuo %s from Vault", mfaDuoPath(name))

	_, err := client.Logical().Delete(mfaDuoPath(name))
	if err != nil {
		return diag.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func mfaDuoRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Id()

	resp, err := client.Logical().Read(mfaDuoPath(name))
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", mfaDuoPath(name))
		d.SetId("")
		return nil
	}

	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}

	log.Printf("[DEBUG] Read MFA Duo config %q", mfaDuoPath(name))

	if err := d.Set(consts.FieldMountAccessor, resp.Data[consts.FieldMountAccessor]); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldUsernameFormat, resp.Data[consts.FieldUsernameFormat]); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldAPIHostname, resp.Data[consts.FieldAPIHostname]); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldPushInfo, resp.Data["pushinfo"]); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(name)

	return nil
}

func mfaDuoUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	if v, ok := d.GetOk(consts.FieldMountAccessor); ok {
		data[consts.FieldMountAccessor] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldUsernameFormat); ok {
		data[consts.FieldUsernameFormat] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldSecretKey); ok {
		data[consts.FieldSecretKey] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldIntegrationKey); ok {
		data[consts.FieldIntegrationKey] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldAPIHostname); ok {
		data[consts.FieldAPIHostname] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldPushInfo); ok {
		data[consts.FieldPushInfo] = v.(string)
	}
}

func mfaDuoPath(name string) string {
	return "sys/mfa/method/duo/" + strings.Trim(name, "/") + "/"
}
