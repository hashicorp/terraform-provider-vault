// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/go-cty/cty"
	automatedrotationutil "github.com/hashicorp/terraform-provider-vault/internal/rotation"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func ldapSecretBackendStaticRoleResource() *schema.Resource {
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
		consts.FieldUsername: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The username of the existing LDAP entry to manage password rotation for.",
			ForceNew:    true,
		},
		consts.FieldDN: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Distinguished name (DN) of the existing LDAP entry to manage password rotation for.",
		},
		consts.FieldSkipImportRotation: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Skip rotation of the password on import.",
		},
		consts.FieldPasswordWO: {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			WriteOnly:   true,
			Description: "Password for the static role. This is required for Vault to manage an existing account and enable rotation.",
		},
		consts.FieldPasswordWOVersion: {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  "Version counter for write-only password.",
			RequiredWith: []string{consts.FieldPasswordWO},
		},
	}
	resource := &schema.Resource{
		CreateContext: createUpdateLDAPStaticRoleResource,
		UpdateContext: createUpdateLDAPStaticRoleResource,
		ReadContext:   provider.ReadContextWrapper(readLDAPStaticRoleResource),
		DeleteContext: deleteLDAPStaticRoleResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}

	// add automated rotation fields to the resource
	provider.MustAddSchema(resource, provider.GetAutomatedRotationSchemaWithPolicy())

	return resource
}

var ldapSecretBackendStaticRoleFields = []string{
	consts.FieldUsername,
	consts.FieldDN,
	consts.FieldRotationPeriod,
	consts.FieldSkipImportRotation,
}

func createUpdateLDAPStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	mount := d.Get(consts.FieldMount).(string)
	role := d.Get(consts.FieldRoleName).(string)
	rolePath := fmt.Sprintf("%s/static-role/%s", mount, role)
	log.Printf("[DEBUG] Creating LDAP static role at %q", rolePath)
	data := map[string]interface{}{}
	for _, field := range ldapSecretBackendStaticRoleFields {
		// omit skip_import_rotation if vault version is less that 1.16 or if this is an update
		// (alternately, only include skip_import_rotation on new resources created on 1.16
		if field == consts.FieldSkipImportRotation && (!provider.IsAPISupported(meta, provider.VaultVersion116) || !d.IsNewResource()) {
			continue
		}
		if v, ok := d.GetOk(field); ok {
			data[field] = v
		}
	}

	// get automated rotation fields
	if provider.IsAPISupported(meta, provider.VaultVersion200) && provider.IsEnterpriseSupported(meta) {
		automatedrotationutil.ParseAutomatedRotationFieldsWithPolicy(d, data)

		// add write-only password field to data if provided
		if d.HasChange(consts.FieldPasswordWOVersion) {
			p := cty.GetAttrPath(consts.FieldPasswordWO)
			woVal, _ := d.GetRawConfigAt(p)
			if !woVal.IsNull() {
				data[consts.FieldPassword] = woVal.AsString()
			}
		}
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
	if err != nil {
		return diag.FromErr(err)
	}

	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", rolePath)
		d.SetId("")
		return nil
	}
	for _, field := range ldapSecretBackendStaticRoleFields {
		if field == consts.FieldSkipImportRotation && !provider.IsAPISupported(meta, provider.VaultVersion116) {
			continue
		}
		if val, ok := resp.Data[field]; ok {
			if err := d.Set(field, val); err != nil {
				return diag.FromErr(fmt.Errorf("error setting state key '%s': %s", field, err))
			}
		}
	}

	// add automated rotation fields automatically
	if provider.IsAPISupported(meta, provider.VaultVersion200) && provider.IsEnterpriseSupported(meta) {
		if err := automatedrotationutil.PopulateAutomatedRotationFieldsWithPolicy(d, resp, rolePath); err != nil {
			return diag.Errorf("error setting automated rotation fields: %s", err)
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
			d.SetId("")
			return nil
		}

		return diag.FromErr(fmt.Errorf("error deleting static role %q: %w", rolePath, err))
	}

	return nil
}
