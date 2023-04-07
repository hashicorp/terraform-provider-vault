// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"log"
)

func ldapSecretBackendStaticRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldBackend: {
			Type:         schema.TypeString,
			Default:      consts.MountTypeLDAP,
			Optional:     true,
			Description:  `The mount path for a backend, for example, the path given in "$ vault secrets enable -path=my-ldap openldap".`,
			ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
		},
		"role": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `Name of the role.`,
			ForceNew:    true,
		},
		consts.FieldUsername: {
			Type:        schema.TypeString,
			Required:    true,
			Description: `The username of the existing LDAP entry to manage password rotation for.`,
			ForceNew:    true,
		},
		"dn": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Distinguished name (DN) of the existing LDAP entry to manage password rotation for.",
		},
		"rotation_period": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "How often Vault should rotate the password of the user entry.",
		},
	}
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: createLDAPStaticRoleResource,
		UpdateContext: createLDAPStaticRoleResource,
		ReadContext:   ReadContextWrapper(readLDAPStaticRoleResource),
		DeleteContext: deleteLDAPStaticRoleResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldBackend),
		Schema:        fields,
	})
}

func createLDAPStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	role := d.Get("role").(string)
	rolePath := fmt.Sprintf("%s/static-role/%s", backend, role)
	log.Printf("[DEBUG] Creating LDAP static role at %q", rolePath)
	data := map[string]interface{}{}
	if v, ok := d.GetOk(consts.FieldUsername); ok {
		data[consts.FieldUsername] = v
	}
	if v, ok := d.GetOk("dn"); ok {
		data["dn"] = v
	}
	if v, ok := d.GetOk("rotation_period"); ok {
		data["rotation_period"] = v
	}

	if _, err := client.Logical().WriteWithContext(ctx, rolePath, data); err != nil {
		return diag.FromErr(fmt.Errorf("error writing %q: %s", rolePath, err))
	}

	d.SetId(rolePath)
	log.Printf("[DEBUG] Wrote %q", rolePath)
	return readLDAPStaticRoleResource(ctx, d, meta)
}

func readLDAPStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	rolePath := d.Id()
	log.Printf("[DEBUG] Reading %q", rolePath)

	resp, err := client.Logical().ReadWithContext(ctx, rolePath)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", rolePath)
		d.SetId("")
		return nil
	}
	if val, ok := resp.Data[consts.FieldUsername]; ok {
		if err := d.Set(consts.FieldUsername, val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key '%s': %s", consts.FieldUsername, err))
		}
	}
	if val, ok := resp.Data["dn"]; ok {
		if err := d.Set("dn", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'dn': %s", err))
		}
	}
	if val, ok := resp.Data["rotation_period"]; ok {
		if err := d.Set("rotation_period", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'rotation_period': %s", err))
		}
	}

	return nil
}

func deleteLDAPStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	rolePath := d.Id()
	_, err = client.Logical().DeleteWithContext(ctx, rolePath)
	if err != nil {
		if util.Is404(err) {
			return nil
		}

		return diag.FromErr(fmt.Errorf("error deleting static role %q: %w", rolePath, err))
	}
	return nil
}
