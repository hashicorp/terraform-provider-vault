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

func tencentCloudAuthBackendClientResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: tencentCloudAuthBackendWrite,
		ReadContext:   provider.ReadContextWrapper(tencentCloudAuthBackendRead),
		UpdateContext: tencentCloudAuthBackendWrite,
		DeleteContext: tencentCloudAuthBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "tencentcloud",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			consts.FieldSecretID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Tencent Cloud Secret ID with permissions to query tencent cloud APIs.",
				Sensitive:   true,
			},
			consts.FieldSecretKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Tencent Cloud Secret key with permissions to query tencent cloud APIs.",
				Sensitive:   true,
			},
		},
	}
}

func tencentCloudAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	// if backend comes from the config, it won't have the StateFunc
	// applied yet, so we need to apply it again.
	backend := d.Get(consts.FieldBackend).(string)
	path := tencentCloudAuthBackendClientPath(backend)

	data := map[string]interface{}{}

	if d.HasChange(consts.FieldSecretID) || d.HasChange(consts.FieldSecretKey) {
		log.Printf("[DEBUG] Updating Tencent Cloud credentials at %q", path)
		data[consts.FieldSecretID] = d.Get(consts.FieldSecretID).(string)
		data[consts.FieldSecretKey] = d.Get(consts.FieldSecretKey).(string)
	}

	log.Printf("[DEBUG] Writing Tencent Cloud auth backend client config to %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error writing to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote tencent cloud auth backend client config to %q", path)

	d.SetId(path)

	return tencentCloudAuthBackendRead(ctx, d, meta)
}

func tencentCloudAuthBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	log.Printf("[DEBUG] Reading Tencent Cloud auth backend client config")
	secret, err := client.Logical().ReadWithContext(ctx, d.Id())
	if err != nil {
		return diag.Errorf("error reading Tencent Cloud auth backend client config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Read Tencent Cloud auth backend client config")

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
	_ = d.Set("backend", re.FindStringSubmatch(d.Id())[1])

	fields := []string{
		consts.FieldSecretID,
		consts.FieldSecretKey,
	}
	for _, k := range fields {
		if v, ok := secret.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
		}
	}
	return nil
}

func tencentCloudAuthBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	log.Printf("[DEBUG] Deleting Tencent Cloud auth backend client config from %q", d.Id())
	_, err := client.Logical().DeleteWithContext(ctx, d.Id())
	if err != nil {
		return diag.Errorf("error deleting Tencent Cloud auth backend client config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Deleted Tencent Cloud auth backend client config from %q", d.Id())

	return nil
}

func tencentCloudAuthBackendClientPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config/client"
}
