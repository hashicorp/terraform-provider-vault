// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func quotaLeaseCountPath(name string) string {
	return "sys/quotas/lease-count/" + name
}

func quotaLeaseCountResource() *schema.Resource {
	return &schema.Resource{
		Create: quotaLeaseCountCreate,
		Read:   provider.ReadWrapper(quotaLeaseCountRead),
		Update: quotaLeaseCountUpdate,
		Delete: quotaLeaseCountDelete,
		Exists: quotaLeaseCountExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the quota.",
				ForceNew:    true,
			},
			consts.FieldPath: {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    false,
				Description: "Path of the mount or namespace to apply the quota. A blank path configures a global lease count quota.",
			},
			"max_leases": {
				Type:         schema.TypeInt,
				Required:     true,
				ForceNew:     false,
				Description:  "The maximum number of leases to be allowed by the quota rule. The max_leases must be positive.",
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
		},
	}
}

func quotaLeaseCountCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Get("name").(string)
	path := quotaLeaseCountPath(name)
	d.SetId(name)

	log.Printf("[DEBUG] Creating Resource Lease Count Quota %s", name)

	data := map[string]interface{}{}
	data["path"] = d.Get("path").(string)
	data["max_leases"] = d.Get("max_leases").(int)

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

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error creating Resource Lease Count Quota %s: %s", name, err)
	}
	log.Printf("[DEBUG] Created Resource Lease Count Quota %s", name)

	return quotaLeaseCountRead(d, meta)
}

func quotaLeaseCountRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()
	path := quotaLeaseCountPath(name)

	log.Printf("[DEBUG] Reading Resource Lease Count Quota %s", name)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading Resource Lease Count Quota %s: %s", name, err)
	}

	if resp == nil {
		log.Printf("[WARN] Resource Lease Count Quota %s not found, removing from state", name)
		d.SetId("")
		return nil
	}

	fields := []string{"path", "max_leases", "name"}
	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		fields = append(fields, consts.FieldRole)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		if _, ok := d.GetOkExists("inheritable"); ok {
			fields = append(fields, "inheritable")
		}
	}

	for _, k := range fields {
		v, ok := resp.Data[k]
		if ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error setting %s for Resource Lease Count Quota %s: %q", k, name, err)
			}
		}
	}

	return nil
}

func quotaLeaseCountUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()
	path := quotaLeaseCountPath(name)

	log.Printf("[DEBUG] Updating Resource Lease Count Quota %s", name)

	data := map[string]interface{}{}
	data["path"] = d.Get(consts.FieldPath).(string)
	data["max_leases"] = d.Get("max_leases").(int)

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		if v, ok := d.GetOk(consts.FieldRole); ok {
			data[consts.FieldRole] = v
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		if v, ok := d.GetOkExists("inheritable"); ok {
			data["inheritable"] = v.(bool)
		}
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error updating Resource Lease Count Quota %s: %s", name, err)
	}
	log.Printf("[DEBUG] Updated Resource Lease Count Quota %s", name)

	return quotaLeaseCountRead(d, meta)
}

func quotaLeaseCountDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()
	path := quotaLeaseCountPath(name)

	log.Printf("[DEBUG] Deleting Resource Lease Count Quota %s", name)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting Resource Lease Count Quota %s", name)
	}
	log.Printf("[DEBUG] Deleted Resource Lease Count Quota %s", name)

	return nil
}

func quotaLeaseCountExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	name := d.Id()
	path := quotaLeaseCountPath(name)

	log.Printf("[DEBUG] Checking if Resource Lease Count Quota %s exists", name)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if Resource Lease Count Quota %s exists: %s", name, err)
	}

	log.Printf("[DEBUG] Checked if Resource Lease Count Quota %s exists", name)
	return secret != nil, nil
}
