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

func ldapSecretBackendStaticRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: ldapSecretBackendStaticRoleCreate,
		UpdateContext: ldapSecretBackendStaticRoleUpdate,
		ReadContext:   ReadContextWrapper(ldapSecretBackendStaticRoleRead),
		DeleteContext: deleteLdapSecretBackendStaticRole,
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
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: `The username of the existing LDAP entry to manage password rotation for.`,
			},
			"dn": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: `Distinguished name (DN) of the existing LDAP entry to manage password rotation for.`,
			},
			"rotation_period": {
				Type:        schema.TypeString,
				Required:    true,
				Description: `How often Vault should rotate the password of the user entry.`,
				StateFunc: func(v interface{}) string {
					duration, _ := time.ParseDuration(v.(string))
					return fmt.Sprintf("%.0f", duration.Seconds())
				},
			},
			"last_vault_rotation": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: ``,
			},
		},
	}
}

func ldapSecretBackendStaticRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	role := d.Get("role_name").(string)
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Creating static role %q on LDAP backend %q", role, mountPath)

	path := mountPath + "/static-role/" + role

	data := map[string]interface{}{}
	configFields := []string{
		"username",
		"dn",
		"rotation_period",
	}
	for _, k := range configFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	log.Printf("[DEBUG] Writing static role %q", path)

	if _, err := client.Logical().Write(path, data); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(role)

	return ldapSecretBackendStaticRoleRead(ctx, d, meta)
}

func ldapSecretBackendStaticRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	diags := diag.Diagnostics{}

	role_name := d.Id()
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Reading static role %q from LDAP backend %q", role_name, mountPath)

	path := mountPath + "/static-role/" + role_name
	config, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading static role from %q: %s", path, err)
	}
	if config == nil {
		log.Printf("[WARN] config (%q) not found, removing from state", path)
		d.SetId("")
		return nil
	}

	configFields := []string{
		"username",
		"dn",
		"rotation_period",
		"last_vault_rotation",
	}
	for _, k := range configFields {
		if err := d.Set(k, config.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	return diags
}

func ldapSecretBackendStaticRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	role_name := d.Id()
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Updating static role %q for LDAP backend %q", role_name, mountPath)

	path := mountPath + "/static-role/" + role_name
	data := map[string]interface{}{}

	configFields := []string{
		"username",
		"dn",
		"rotation_period",
	}
	for _, k := range configFields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	if len(data) > 0 {
		log.Printf("[DEBUG] Updating %q", path)

		if _, err := client.Logical().Write(path, data); err != nil {
			return diag.Errorf("error writing config to static role %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated %q", path)
	} else {
		log.Printf("[DEBUG] Nothing to update for %q", path)
	}

	return ldapSecretBackendStaticRoleRead(ctx, d, meta)
}

func deleteLdapSecretBackendStaticRole(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	role_name := d.Id()
	mountPath := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Deleting static role %q from LDAP backend %q", role_name, mountPath)

	path := mountPath + "/static-role/" + role_name
	if _, err := client.Logical().Delete(path); err != nil {
		return diag.Errorf("error deleting role %q from mount %q: %s", role_name, mountPath, err)
	}

	log.Printf("[DEBUG] Deleted static role %q from LDAP backend %q", role_name, mountPath)

	return nil
}
