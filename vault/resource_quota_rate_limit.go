// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func quotaRateLimitPath(name string) string {
	return "sys/quotas/rate-limit/" + name
}

func quotaRateLimitResource() *schema.Resource {
	return &schema.Resource{
		Create: quotaRateLimitCreate,
		Read:   provider.ReadWrapper(quotaRateLimitRead),
		Update: quotaRateLimitUpdate,
		Delete: quotaRateLimitDelete,
		Exists: quotaRateLimitExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		CustomizeDiff: quotaRateLimitCustomizeDiff,
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
			"secondary_rate": {
				Type:         schema.TypeFloat,
				Optional:     true,
				Computed:     true,
				Description:  `Only available when using the "entity_then_ip" or "entity_then_none" group_by modes. This is the rate limit applied to the requests that fall under the "ip" or "none" groupings, while the authenticated requests that contain an entity ID are subject to the "rate" field instead. Defaults to the same value as "rate".`,
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
			consts.FieldRole: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "If set on a quota where path is set to an auth mount with a concept of roles (such as /auth/approle/), this will make the quota restrict login requests to that mount that are made with the specified role.",
			},
			"inheritable": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set to true on a quota where path is set to a namespace, the same quota will be cumulatively applied to all child namespace. The inheritable parameter cannot be set to true if the path does not specify a namespace. Only the quotas associated with the root namespace are inheritable by default.",
			},
			"group_by": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: `Attribute used to group requests for rate limiting. Limits are enforced independently` +
					` for each group. Valid group_by modes are: 1) "ip" that groups requests by their source IP` +
					` address (group_by defaults to ip if unset); 2) "none" that groups all requests that match the` +
					` rate limit quota rule together; 3) "entity_then_ip" that groups requests by their entity ID for` +
					` authenticated requests that carry one, or by their IP for unauthenticated requests (or requests` +
					` whose authentication is not connected to an entity); and 4) "entity_then_none" which also` +
					` groups requests by their entity ID when available, but the rest is all grouped together (i.e.` +
					` unauthenticated or with authentication not connected to an entity).`,
				ValidateFunc: validation.StringInSlice([]string{"ip", "none", "entity_then_ip", "entity_then_none"}, false),
			},
		},
	}
}

func quotaRateLimitCustomizeDiff(ctx context.Context, d *schema.ResourceDiff, meta interface{}) error {
	// cross-field validation: secondary_rate can only be set if group_by is set to "entity_then_ip" or "entity_then_none"
	if _, ok := d.GetOk("secondary_rate"); ok {
		groupBy, ok := d.GetOk("group_by")
		if !ok {
			return fmt.Errorf("secondary_rate can only be set if group_by is set to 'entity_then_ip' or 'entity_then_none'")
		}
		if groupBy != "entity_then_ip" && groupBy != "entity_then_none" {
			return fmt.Errorf("secondary_rate can only be set if group_by is set to 'entity_then_ip' or 'entity_then_none', but got %s", groupBy)
		}
	}

	return nil
}

func quotaRateLimitCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
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

	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		if v, ok := d.GetOkExists("inheritable"); ok {
			data["inheritable"] = v.(bool)
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		if v, ok := d.GetOk(consts.FieldRole); ok {
			data[consts.FieldRole] = v
		}
	}

	if v, ok := d.GetOk("group_by"); ok {
		if !provider.IsAPISupported(meta, provider.VaultVersion120) {
			d.SetId("")
			return fmt.Errorf("group_by is only supported in Vault Enterprise 1.20 and later")
		}
		data["group_by"] = v
	}

	if v, ok := d.GetOk("secondary_rate"); ok {
		if !provider.IsAPISupported(meta, provider.VaultVersion120) {
			d.SetId("")
			return fmt.Errorf("secondary_rate is only supported in Vault Enterprise 1.20 and later")
		}
		data["secondary_rate"] = v
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error creating Resource Rate Limit Quota %s: %s", name, err)
	}
	log.Printf("[DEBUG] Created Resource Rate Limit Quota %s", name)

	return quotaRateLimitRead(d, meta)
}

func quotaRateLimitRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()
	path := quotaRateLimitPath(name)

	log.Printf("[DEBUG] Reading Resource Rate Limit Quota %s", name)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading Resource Rate Limit Quota %s: %s", name, err)
	}

	if resp == nil {
		log.Printf("[WARN] Resource Rate Limit Quota %s not found, removing from state", name)
		d.SetId("")
		return nil
	}

	fields := []string{"path", "rate", "interval", "block_interval", "name"}
	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		fields = append(fields, consts.FieldRole)
	}

	// If not explicitly set by the user the backend will use a sane default depending on the path, but we can't
	// reflect it on the state because the field is not computed. We could make it optional+computed, but making it
	// computed would mean a diff on upgrade, which could be considered a breaking change. This approach also doesn't
	// work with the import command.
	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		if _, ok := d.GetOkExists("inheritable"); ok {
			fields = append(fields, "inheritable")
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion120) {
		fields = append(fields, "group_by", "secondary_rate")
	}

	for _, k := range fields {
		v, ok := resp.Data[k]
		if ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error setting %s for Resource Rate Limit Quota %s: %q", k, name, err)
			}
		}
	}

	return nil
}

func quotaRateLimitUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
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

	if v, ok := d.GetOk("group_by"); ok {
		if !provider.IsAPISupported(meta, provider.VaultVersion120) {
			return fmt.Errorf("group_by is only supported in Vault Enterpprise 1.20 and later")
		}
		data["group_by"] = v
	}

	if v, ok := d.GetOk("secondary_rate"); ok {
		if !provider.IsAPISupported(meta, provider.VaultVersion120) {
			return fmt.Errorf("secondary_rate is only supported in Vault Enterprise 1.20 and later")
		}
		data["secondary_rate"] = v
	}

	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		// we should probably fail if the field is set on an unsupported version instead of ignoring it, but changing
		// that would be a breaking change
		if v, ok := d.GetOkExists("inheritable"); ok {
			data["inheritable"] = v.(bool)
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		// we should probably fail if the field is set on an unsupported version instead of ignoring it, but changing
		// that would be a breaking change
		if v, ok := d.GetOk(consts.FieldRole); ok {
			data[consts.FieldRole] = v
		}
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("Error updating Resource Rate Limit Quota %s: %s", name, err)
	}
	log.Printf("[DEBUG] Updated Resource Rate Limit Quota %s", name)

	return quotaRateLimitRead(d, meta)
}

func quotaRateLimitDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()
	path := quotaRateLimitPath(name)

	log.Printf("[DEBUG] Deleting Resource Rate Limit Quota %s", name)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting Resource Rate Limit Quota %s", name)
	}
	log.Printf("[DEBUG] Deleted Resource Rate Limit Quota %s", name)

	return nil
}

func quotaRateLimitExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	name := d.Id()
	path := quotaRateLimitPath(name)

	log.Printf("[DEBUG] Checking if Resource Rate Limit Quota %s exists", name)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if Resource Rate Limit Quota %s exists: %s", name, err)
	}

	log.Printf("[DEBUG] Checked if Resource Rate Limit Quota %s exists", name)
	return secret != nil, nil
}
