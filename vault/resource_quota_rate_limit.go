// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func quotaRateLimitPath(name string) string {
	return "sys/quotas/rate-limit/" + name
}

func quotaRateLimitResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: quotaRateLimitCreate,
		ReadContext:   ReadContextWrapper(quotaRateLimitRead),
		UpdateContext: quotaRateLimitUpdate,
		DeleteContext: quotaRateLimitDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the quota.",
				ForceNew:    true,
			},
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Path of the mount or namespace to apply the quota. A blank path configures a global rate limit quota.",
			},
			"rate": {
				Type:         schema.TypeFloat,
				Required:     true,
				Description:  "The maximum number of requests at any given second to be allowed by the quota rule. The rate must be positive.",
				ValidateFunc: validation.FloatAtLeast(0.0),
			},
			"interval": {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "The duration in seconds to enforce rate limiting for.",
				ValidateFunc: validation.IntAtLeast(1),
				Computed:     true,
			},
			"block_interval": {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "If set, when a client reaches a rate limit threshold, the client will be prohibited from any further requests until after the 'block_interval' in seconds has elapsed.",
				ValidateFunc: validation.IntAtLeast(0),
			},
		},
	}
}

func quotaRateLimitCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get("name").(string)
	path := quotaRateLimitPath(name)
	d.SetId(name)

	log.Printf("[DEBUG] Creating Resource Rate Limit Quota %s", name)

	data := map[string]interface{}{}
	data["path"] = d.Get("path").(string)
	data["rate"] = d.Get("rate").(float64)

	if v, ok := d.GetOk("interval"); ok {
		data["interval"] = v
	}

	if v, ok := d.GetOk("block_interval"); ok {
		data["block_interval"] = v
	}

	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("Error creating Resource Rate Limit Quota %s: %s", name, err)
	}
	log.Printf("[DEBUG] Created Resource Rate Limit Quota %s", name)

	return quotaRateLimitRead(ctx, d, meta)
}

func quotaRateLimitRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Id()
	path := quotaRateLimitPath(name)

	log.Printf("[DEBUG] Reading Resource Rate Limit Quota %s", name)
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading Resource Rate Limit Quota %s: %s", name, err)
	}

	if resp == nil {
		log.Printf("[WARN] Resource Rate Limit Quota %s not found, removing from state", name)
		d.SetId("")
		return nil
	}

	for _, k := range []string{"path", "rate", "interval", "block_interval"} {
		v, ok := resp.Data[k]
		if ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error setting %s for Resource Rate Limit Quota %s: %q", k, name, err)
			}
		}
	}

	return nil
}

func quotaRateLimitUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Id()
	path := quotaRateLimitPath(name)

	log.Printf("[DEBUG] Updating Resource Rate Limit Quota %s", name)

	data := map[string]interface{}{}
	data["path"] = d.Get("path").(string)
	data["rate"] = d.Get("rate").(float64)

	if v, ok := d.GetOk("interval"); ok {
		data["interval"] = v
	}

	if v, ok := d.GetOk("block_interval"); ok {
		data["block_interval"] = v
	}

	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("Error updating Resource Rate Limit Quota %s: %s", name, err)
	}
	log.Printf("[DEBUG] Updated Resource Rate Limit Quota %s", name)

	return quotaRateLimitRead(ctx, d, meta)
}

func quotaRateLimitDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Id()
	path := quotaRateLimitPath(name)

	log.Printf("[DEBUG] Deleting Resource Rate Limit Quota %s", name)
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("Error deleting Resource Rate Limit Quota %s", name)
	}
	log.Printf("[DEBUG] Deleted Resource Rate Limit Quota %s", name)

	return nil
}
