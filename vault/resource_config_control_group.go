// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"

	"github.com/hashicorp/go-secure-stdlib/parseutil"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	controlGroupPath = "sys/config/control-group"
)

func configControlGroupResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: configControlGroupWrite,
		UpdateContext: configControlGroupWrite,
		ReadContext:   provider.ReadContextWrapper(configControlGroupRead),
		DeleteContext: configControlGroupDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			consts.FieldMaxTTL: {
				Type:                  schema.TypeString,
				Optional:              true,
				Description:           "The maximum TTL for a control group wrapping token.",
				DiffSuppressFunc:      configControlGroupSuppressMaxTTLDiff,
				DiffSuppressOnRefresh: true,
			},
		},
	}
}

func configControlGroupSuppressMaxTTLDiff(_ string, oldValue, newValue string, _ *schema.ResourceData) bool {
	oldDuration, oldErr := parseutil.ParseDurationSecond(oldValue)
	newDuration, newErr := parseutil.ParseDurationSecond(newValue)
	if oldErr != nil || newErr != nil {
		return false
	}

	return oldDuration == newDuration
}

func configControlGroupWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	data := map[string]interface{}{}

	if v, ok := d.GetOk(consts.FieldMaxTTL); ok {
		data[consts.FieldMaxTTL] = v.(string)
	}

	log.Printf("[DEBUG] Writing control group configuration to %q", controlGroupPath)
	_, err := client.Logical().WriteWithContext(ctx, controlGroupPath, data)
	if err != nil {
		return diag.Errorf("error writing %q: %s", controlGroupPath, err)
	}
	log.Printf("[DEBUG] Wrote control group configuration to %q", controlGroupPath)

	d.SetId(controlGroupPath)

	return configControlGroupRead(ctx, d, meta)
}

func configControlGroupRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	log.Printf("[DEBUG] Reading control group configuration from %q", controlGroupPath)

	resp, err := client.Logical().ReadWithContext(ctx, controlGroupPath)
	if err != nil {
		return diag.Errorf("error reading %q: %s", controlGroupPath, err)
	}

	if resp == nil {
		log.Printf("[WARN] Control group configuration %q not found, removing from state", controlGroupPath)
		d.SetId("")
		return nil
	}

	if val, ok := resp.Data[consts.FieldMaxTTL]; ok {
		if err := d.Set(consts.FieldMaxTTL, val); err != nil {
			return diag.Errorf("error setting state key '%s': %s", consts.FieldMaxTTL, err)
		}
	}

	return nil
}

func configControlGroupDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	log.Printf("[DEBUG] Deleting control group configuration from %q", controlGroupPath)

	_, err := client.Logical().DeleteWithContext(ctx, controlGroupPath)
	if err != nil {
		return diag.Errorf("error deleting %q: %s", controlGroupPath, err)
	}

	log.Printf("[DEBUG] Deleted control group configuration from %q", controlGroupPath)
	return nil
}
