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

func ldapSecretBackendDynamicRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: ldapSecretBackendDynamicRoleCreate,
		UpdateContext: ldapSecretBackendDynamicRoleUpdate,
		ReadContext:   ReadContextWrapper(ldapSecretBackendDynamicRoleRead),
		DeleteContext: deleteLdapSecretBackendDynamicRole,
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
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: `The name of the dynamic role.`,
			},
			"creation_ldif": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: `A templatized LDIF string used to create a user account. This may contain multiple LDIF entries.`,
			},
			"deletion_ldif": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: `A templatized LDIF string used to delete the user account once its TTL has expired.`,
			},
			"rollback_ldif": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: `A templatized LDIF string used to attempt to rollback any changes in the event that execution of the creation_ldif results in an error.`,
			},
			"username_template": {
				Type:        schema.TypeString,
				Default:     "v_{{.DisplayName}}_{{.RoleName}}_{{random 10}}_{{unix_time}}",
				Optional:    true,
				Description: `A template used to generate a dynamic username. This will be used to fill in the .Username field within the creation_ldif string.`,
			},
			"default_ttl": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: `Specifies the TTL for the leases associated with this role. Accepts duration format strings. Defaults to system/engine default TTL time.`,
				StateFunc: func(v interface{}) string {
					duration, _ := time.ParseDuration(v.(string))
					return fmt.Sprintf("%.0f", duration.Seconds())
				},
			},
			"max_ttl": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: `Specifies the maximum TTL for the leases associated with this role. Accepts duration format strings.`,
				StateFunc: func(v interface{}) string {
					duration, _ := time.ParseDuration(v.(string))
					return fmt.Sprintf("%.0f", duration.Seconds())
				},
			},
		},
	}
}

func ldapSecretBackendDynamicRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	role_name := d.Get("role_name").(string)
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Creating dynamic role %q on LDAP backend %q", role_name, mountPath)

	path := mountPath + "/role/" + role_name

	data := map[string]interface{}{}
	configFields := []string{
		"role_name",
		"creation_ldif",
		"deletion_ldif",
		"rollback_ldif",
		"username_template",
		"default_ttl",
		"max_ttl",
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

	d.SetId(role_name)

	return ldapSecretBackendDynamicRoleRead(ctx, d, meta)
}

func ldapSecretBackendDynamicRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	diags := diag.Diagnostics{}

	role_name := d.Id()
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Reading dynamic role %q from LDAP backend %q", role_name, mountPath)

	path := mountPath + "/role/" + role_name
	config, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading dynamic role from %q: %s", path, err)
	}
	if config == nil {
		log.Printf("[WARN] config (%q) not found, removing from state", path)
		d.SetId("")
		return nil
	}

	configFields := []string{
		"role_name",
		"creation_ldif",
		"deletion_ldif",
		"rollback_ldif",
		"username_template",
		"default_ttl",
		"max_ttl",
	}
	for _, k := range configFields {
		if err := d.Set(k, config.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	return diags
}

func ldapSecretBackendDynamicRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	role_name := d.Id()
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Updating dynamic role %q for LDAP backend %q", role_name, mountPath)

	path := mountPath + "/role/" + role_name
	data := map[string]interface{}{}

	configFields := []string{
		"role_name",
		"creation_ldif",
		"deletion_ldif",
		"rollback_ldif",
		"username_template",
		"default_ttl",
		"max_ttl",
	}
	for _, k := range configFields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	if len(data) > 0 {
		log.Printf("[DEBUG] Updating %q", path)

		if _, err := client.Logical().Write(path, data); err != nil {
			return diag.Errorf("error writing config to dynamic role %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated %q", path)
	} else {
		log.Printf("[DEBUG] Nothing to update for %q", path)
	}

	return ldapSecretBackendDynamicRoleRead(ctx, d, meta)
}

func deleteLdapSecretBackendDynamicRole(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	role_name := d.Id()
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Deleting dynamic role %q from LDAP backend %q", role_name, mountPath)

	path := mountPath + "/role/" + role_name
	if _, err := client.Logical().Delete(path); err != nil {
		return diag.Errorf("error deleting role %q from mount %q: %s", role_name, mountPath, err)
	}

	log.Printf("[DEBUG] Deleted dynamic role %q from LDAP backend %q", role_name, mountPath)

	return nil
}
