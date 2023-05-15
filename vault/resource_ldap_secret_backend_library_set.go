// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func ldapSecretBackendLibrarySetResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: ldapSecretBackendLibrarySetCreate,
		UpdateContext: ldapSecretBackendLibrarySetUpdate,
		ReadContext:   ReadContextWrapper(ldapSecretBackendLibrarySetRead),
		DeleteContext: deleteLdapSecretBackendLibrarySet,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				Description: `The mount path for a backend, for example, the path given in "$ vault auth enable -path=ldap ldap".`,
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"set_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: `The name of the set of service accounts.`,
			},
			"service_account_names": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Required:    true,
				Description: `The names of all the service accounts that can be checked out from this set.`,
			},
			"ttl": {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
				StateFunc: func(v interface{}) string {
					duration, _ := time.ParseDuration(v.(string))
					return fmt.Sprintf("%.0f", duration.Seconds())
				},
				Description: `The maximum amount of time a single check-out lasts before Vault automatically checks it back in.`,
			},
			"max_ttl": {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
				StateFunc: func(v interface{}) string {
					duration, _ := time.ParseDuration(v.(string))
					return fmt.Sprintf("%.0f", duration.Seconds())
				},
				Description: `Specifies the maximum TTL for the leases associated with this role. Accepts duration format strings.`,
			},
			"disable_check_in_enforcement": {
				Type:        schema.TypeBool,
				Computed:    true,
				Optional:    true,
				Description: `Specifies the maximum TTL for the leases associated with this role. Accepts duration format strings.`,
			},
		},
	}
}

func ldapSecretBackendLibrarySetCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	set_name := d.Get("set_name").(string)
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Creating library set %q on LDAP backend %q", set_name, mountPath)

	path := mountPath + "/library/" + set_name

	data := map[string]interface{}{}
	data["name"] = set_name
	if v, ok := d.GetOk("service_account_names"); ok {
		data["service_account_names"] = v.(*schema.Set).List()
	}
	configFields := []string{
		"ttl",
		"max_ttl",
		"disable_check_in_enforcement",
	}
	for _, k := range configFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	log.Printf("[DEBUG] Writing dynamic role %q", path)

	if _, err := client.Logical().Write(path, data); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(set_name)

	return ldapSecretBackendLibrarySetRead(ctx, d, meta)
}

func ldapSecretBackendLibrarySetRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	diags := diag.Diagnostics{}

	set_name := d.Id()
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Reading library set %q from LDAP backend %q", set_name, mountPath)

	path := mountPath + `/library/` + set_name
	config, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading library set from %q: %s", path, err)
	}
	if config == nil {
		log.Printf("[WARN] config (%q) not found, removing from state", path)
		d.SetId("")
		return nil
	}

	configFields := []string{
		"service_account_names",
		"ttl",
		"max_ttl",
		"disable_check_in_enforcement",
	}
	for _, k := range configFields {
		if err := d.Set(k, config.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	return diags
}

func ldapSecretBackendLibrarySetUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	set_name := d.Id()
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Updating library set %q for LDAP backend %q", set_name, mountPath)

	path := mountPath + `/library/` + set_name
	data := map[string]interface{}{}

	configFields := []string{
		"service_account_names",
		"ttl",
		"max_ttl",
		"disable_check_in_enforcement",
	}
	for _, k := range configFields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	if len(data) > 0 {
		log.Printf("[DEBUG] Updating %q", path)

		if _, err := client.Logical().Write(path, data); err != nil {
			return diag.Errorf("error writing config to library set %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated %q", path)
	} else {
		log.Printf("[DEBUG] Nothing to update for %q", path)
	}

	return ldapSecretBackendLibrarySetRead(ctx, d, meta)
}

func deleteLdapSecretBackendLibrarySet(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	set_name := d.Id()
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Deleting dynamic role %q from LDAP backend %q", set_name, mountPath)

	path := mountPath + `/library/` + set_name
	if _, err := client.Logical().Delete(path); err != nil {
		return diag.Errorf("error deleting role %q from mount %q: %s", set_name, mountPath, err)
	}

	log.Printf("[DEBUG] Deleted dynamic role %q from LDAP backend %q", set_name, mountPath)

	return nil
}
