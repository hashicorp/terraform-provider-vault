// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/go-cty/cty"
	automatedrotationutil "github.com/hashicorp/terraform-provider-vault/internal/rotation"

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
		consts.FieldPasswordPolicy: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Name of the password policy to use to generate passwords for this role.",
		},
		consts.FieldRotateOnRead: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "If true, credentials are rotated on each read. Overrides the engine-level default when set. Requires Vault Enterprise ≥ 2.1.0.",
		},
		consts.FieldRotateOnReadCooldown: {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "Minimum seconds between rotate-on-read rotations for this role. Overrides the engine-level default when set. Requires Vault Enterprise ≥ 2.1.0.",
		},
		consts.FieldAutoUnlock: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
			Description: "Overrides the mount-level auto_unlock setting for this role. " +
				"When true, Vault unlocks the account automatically after a successful rotation. " +
				"When false, disables automatic unlock even if the mount enables it. " +
				"When unset, inherits the mount-level setting. " +
				"Currently only the Active Directory schema is supported. Requires Vault 2.1+",
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
	consts.FieldPasswordPolicy,
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

	// Handle password_policy unsetting: if the field changed from set to unset,
	// send an empty string to clear the role-level override and inherit mount-level policy.
	// validate that password_policy is only used with Vault >= 2.1.0.
	if d.HasChange(consts.FieldPasswordPolicy) {
		if _, ok := d.GetOk(consts.FieldPasswordPolicy); !ok {
			// Field was removed from config, send empty string to clear it
			data[consts.FieldPasswordPolicy] = ""
		} else if !provider.IsAPISupported(meta, provider.VaultVersion210) {
			return diag.Errorf("password_policy is only supported in Vault 2.1.0 and later")
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

	// get rotate-on-read role-level overrides
	if provider.IsAPISupported(meta, provider.VaultVersion210) && provider.IsEnterpriseSupported(meta) {
		if d.HasChange(consts.FieldRotateOnRead) {
			data[consts.FieldRotateOnRead] = d.Get(consts.FieldRotateOnRead)
		}
		if d.HasChange(consts.FieldRotateOnReadCooldown) {
			data[consts.FieldRotateOnReadCooldown] = d.Get(consts.FieldRotateOnReadCooldown)
		}
	}

	// only send auto_unlock if explicitly set — avoids overwriting mount-level default with false
	if provider.IsAPISupported(meta, provider.VaultVersion210) && provider.IsEnterpriseSupported(meta) {
		if d.HasChange(consts.FieldAutoUnlock) {
			data[consts.FieldAutoUnlock] = d.Get(consts.FieldAutoUnlock)
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

	if provider.IsAPISupported(meta, provider.VaultVersion210) && provider.IsEnterpriseSupported(meta) {
		if v, ok := resp.Data[consts.FieldRotateOnRead]; ok {
			if err := d.Set(consts.FieldRotateOnRead, v); err != nil {
				return diag.Errorf("error setting %s: %s", consts.FieldRotateOnRead, err)
			}
		}
		if v, ok := resp.Data[consts.FieldRotateOnReadCooldown]; ok {
			if err := d.Set(consts.FieldRotateOnReadCooldown, v); err != nil {
				return diag.Errorf("error setting %s: %s", consts.FieldRotateOnReadCooldown, err)
			}
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion210) && provider.IsEnterpriseSupported(meta) {
		if val, ok := resp.Data[consts.FieldAutoUnlock]; ok {
			if err := d.Set(consts.FieldAutoUnlock, val); err != nil {
				return diag.FromErr(fmt.Errorf("error setting auto unlock field '%s': %s", consts.FieldAutoUnlock, err))
			}
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
