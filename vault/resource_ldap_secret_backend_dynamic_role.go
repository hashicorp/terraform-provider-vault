// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func ldapSecretBackendDynamicRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldMount: {
			Type:         schema.TypeString,
			Default:      consts.MountTypeLDAP,
			Optional:     true,
			Description:  "The path where the LDAP secrets backend is mounted.",
			ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
		},
		consts.FieldRoleName: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role.",
			ForceNew:    true,
		},
		consts.FieldCreationLDIF: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "A templatized LDIF string used to create a user account. May contain multiple entries.",
		},
		consts.FieldDeletionLDIF: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "A templatized LDIF string used to delete the user account once its TTL has expired. This may contain multiple LDIF entries.",
		},
		consts.FieldRollbackLDIF: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "A templatized LDIF string used to attempt to rollback any changes in the event that execution of the creation_ldif results in an error. This may contain multiple LDIF entries.",
		},
		consts.FieldUsernameTemplate: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "A template used to generate a dynamic username. This will be used to fill in the .Username field within the creation_ldif string.",
		},
		consts.FieldDefaultTTL: {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "Specifies the TTL for the leases associated with this role.",
		},
		consts.FieldMaxTTL: {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "Specifies the maximum TTL for the leases associated with this role.",
		},
	}
	return &schema.Resource{
		CreateContext: createUpdateLDAPDynamicRoleResource,
		UpdateContext: createUpdateLDAPDynamicRoleResource,
		ReadContext:   provider.ReadContextWrapper(readLDAPDynamicRoleResource),
		DeleteContext: deleteLDAPDynamicRoleResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

var ldapSecretBackendDynamicRoleFields = []string{
	consts.FieldCreationLDIF,
	consts.FieldDeletionLDIF,
	consts.FieldRollbackLDIF,
	consts.FieldUsernameTemplate,
	consts.FieldDefaultTTL,
	consts.FieldMaxTTL,
}

func createUpdateLDAPDynamicRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	mount := d.Get(consts.FieldMount).(string)
	role := d.Get(consts.FieldRoleName).(string)
	rolePath := fmt.Sprintf("%s/role/%s", mount, role)
	log.Printf("[DEBUG] Creating LDAP dynamic role at %q", rolePath)
	data := map[string]interface{}{}
	for _, field := range ldapSecretBackendDynamicRoleFields {
		if v, ok := d.GetOk(field); ok {
			data[field] = v
		}
	}

	if _, err := client.Logical().WriteWithContext(ctx, rolePath, data); err != nil {
		return diag.FromErr(fmt.Errorf("error writing %q: %s", rolePath, err))
	}

	d.SetId(rolePath)
	log.Printf("[DEBUG] Wrote %q", rolePath)
	return readLDAPDynamicRoleResource(ctx, d, meta)
}

func readLDAPDynamicRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
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

	for _, field := range ldapSecretBackendDynamicRoleFields {
		if val, ok := resp.Data[field]; ok {
			if err := d.Set(field, val); err != nil {
				return diag.FromErr(fmt.Errorf("error setting state key '%s': %s", field, err))
			}
		}
	}

	return nil
}

func deleteLDAPDynamicRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	rolePath := d.Id()
	_, err = client.Logical().DeleteWithContext(ctx, rolePath)
	if err != nil {
		if util.Is404(err) {
			d.SetId("")
			return nil
		}

		return diag.FromErr(fmt.Errorf("error deleting dynamic role %q: %w", rolePath, err))
	}

	return nil
}
