// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	databaseSecretBackendStaticRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/static-roles/.+$")
	databaseSecretBackendStaticRoleNameFromPathRegex    = regexp.MustCompile("^.+/static-roles/(.+$)")
)

var staticRoleFields = []string{
	consts.FieldRotationPeriod,
	consts.FieldRotationStatements,
	consts.FieldDBName,
	consts.FieldCredentialType,
	consts.FieldCredentialConfig,
}

func databaseSecretBackendStaticRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: databaseSecretBackendStaticRoleWrite,
		ReadContext:   provider.ReadContextWrapper(databaseSecretBackendStaticRoleRead),
		UpdateContext: databaseSecretBackendStaticRoleWrite,
		DeleteContext: databaseSecretBackendStaticRoleDelete,
		CustomizeDiff: validatePasswordFields,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the static role.",
			},
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the Database Secret Backend the role belongs to.",
			},
			consts.FieldUsername: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The database username that this role corresponds to.",
			},
			consts.FieldRotationPeriod: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The amount of time Vault should wait before rotating the password, in seconds.",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(int)
					if value < 5 {
						errs = append(errs, fmt.Errorf("The minimum value of rotation_period is 5 seconds."))
					}
					return
				},
			},
			consts.FieldRotationSchedule: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A cron-style string that will define the schedule on which rotations should occur.",
			},
			consts.FieldRotationWindow: {
				Type:     schema.TypeInt,
				Optional: true,
				Description: "The amount of time in seconds in which the rotations are allowed to occur starting " +
					"from a given rotation_schedule.",
			},
			consts.FieldDBName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Database connection to use for this role.",
			},
			consts.FieldRotationStatements: {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Database statements to execute to rotate the password for the configured database user.",
			},
			consts.FieldSelfManagedPassword: {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Description: "The password corresponding to the username in the database. " +
					"Required when using the Rootless Password Rotation workflow for static roles. " +
					"Deprecated in favor of password_wo field introduced in Vault 1.19.",
			},
			consts.FieldPasswordWO: {
				Type:      schema.TypeString,
				Optional:  true,
				WriteOnly: true,
				Description: "The password corresponding to the username in the database. " +
					"This is a write-only field. Requires Vault 1.19+. " +
					"Deprecates 'self_managed_password' which was introduced in Vault 1.18.",
			},
			consts.FieldPasswordWOVersion: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The version of the password_wo field. Used for tracking changes to the write-only password field.",
			},
			consts.FieldSkipImportRotation: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Skip rotation of the password on import. When not set, inherits from connection's skip_static_role_import_rotation.",
			},
			consts.FieldCredentialType: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "The credential type for the user, can be one of \"password\", \"rsa_private_key\" or \"client_certificate\"." +
					"The configuration can be done in `credential_config`.",
			},
			consts.FieldCredentialConfig: {
				Type:     schema.TypeMap,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Description: "The configuration for the credential type." +
					"Full documentation for the allowed values can be found under \"https://developer.hashicorp.com/vault/api-docs/secret/databases#credential_config\".",
			},
		},
	}
}

func databaseSecretBackendStaticRoleWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	name := d.Get(consts.FieldName).(string)

	path := databaseSecretBackendStaticRolePath(backend, name)

	data := map[string]interface{}{
		"username":            d.Get(consts.FieldUsername),
		"db_name":             d.Get(consts.FieldDBName),
		"rotation_statements": []string{},
	}

	useAPIVer115 := provider.IsAPISupported(meta, provider.VaultVersion115)
	if useAPIVer115 {
		if v, ok := d.GetOk(consts.FieldRotationSchedule); ok && v != "" {
			data[consts.FieldRotationSchedule] = v
		}
		if v, ok := d.GetOk(consts.FieldRotationWindow); ok && v != "" {
			data[consts.FieldRotationWindow] = v
		}
	}

	if v, ok := d.GetOk(consts.FieldRotationStatements); ok && v != "" {
		data[consts.FieldRotationStatements] = v
	}

	if v, ok := d.GetOk(consts.FieldRotationPeriod); ok && v != "" {
		data[consts.FieldRotationPeriod] = v
	}

	if v, ok := d.GetOk(consts.FieldCredentialType); ok && v != "" {
		data[consts.FieldCredentialType] = v
	}

	if v, ok := d.GetOk(consts.FieldCredentialConfig); ok && v != "" {
		data[consts.FieldCredentialConfig] = v
	}

	if provider.IsAPISupported(meta, provider.VaultVersion118) && provider.IsEnterpriseSupported(meta) {
		if v, ok := d.GetOk(consts.FieldSelfManagedPassword); ok && v != "" {
			data[consts.FieldSelfManagedPassword] = v
		}
		// Only send skip_import_rotation if explicitly set in config
		// Use GetRawConfig to distinguish between "not set" and "set to false"
		skipImportAttr := d.GetRawConfig().GetAttr(consts.FieldSkipImportRotation)
		if !skipImportAttr.IsNull() && skipImportAttr.IsKnown() {
			data[consts.FieldSkipImportRotation] = skipImportAttr.True()
		} else {
			log.Printf("[DEBUG] skip_import_rotation not set in config, sending nil to Vault")
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		// Handle password write-only field for Vault 1.19+
		// Send password on creation (d.IsNewResource()) OR when version changes
		if d.IsNewResource() || d.HasChange(consts.FieldPasswordWOVersion) {
			// Use GetRawConfig for write-only fields (same pattern as terraform_cloud_secret_backend)
			pwWo := d.GetRawConfig().GetAttr(consts.FieldPasswordWO)
			if pwWo.IsKnown() && !pwWo.IsNull() && strings.TrimSpace(pwWo.AsString()) != "" {
				data[consts.FieldPassword] = pwWo.AsString()
			}
		}
	}

	log.Printf("[DEBUG] Creating static role %q on database backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating static role %q for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created static role %q on AWS backend %q", name, backend)

	d.SetId(path)
	return databaseSecretBackendStaticRoleRead(ctx, d, meta)
}

func databaseSecretBackendStaticRoleRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	name, err := databaseSecretBackendStaticRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing database static role %q because its ID is invalid", path)
		d.SetId("")
		return diag.Errorf("invalid static role ID %q: %s", path, err)
	}

	backend, err := databaseSecretBackendStaticRoleBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing database static role %q because its ID is invalid", path)
		d.SetId("")
		return diag.Errorf("invalid static role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading static role from %q", path)
	role, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading static role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read static role from %q", path)
	if role == nil {
		log.Printf("[WARN] Static role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldUsername, role.Data[consts.FieldUsername]); err != nil {
		return diag.FromErr(err)
	}

	useAPIVer115 := provider.IsAPISupported(meta, provider.VaultVersion115)
	if useAPIVer115 {
		if err := d.Set(consts.FieldRotationSchedule, role.Data[consts.FieldRotationSchedule]); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set(consts.FieldRotationWindow, role.Data[consts.FieldRotationWindow]); err != nil {
			return diag.FromErr(err)
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion118) && provider.IsEnterpriseSupported(meta) {
		// Always read skip_import_rotation from Vault's response.
		// When not set in config, Vault computes this value based on
		// the connection's skip_static_role_import_rotation setting.
		if v, ok := role.Data[consts.FieldSkipImportRotation]; ok && v != nil {
			log.Printf("[DEBUG] Vault returned skip_import_rotation: %v (type: %T)", v, v)
			if err := d.Set(consts.FieldSkipImportRotation, v); err != nil {
				return diag.FromErr(err)
			}
		}
		log.Printf("[DEBUG] Vault response does not contain skip_import_rotation")
	}

	// Note: password_wo_version is not explicitly set in Read function.
	// It's a client-side tracking field that Terraform SDK manages automatically.
	// This follows the pattern used by other resources with write-only version fields
	// (gcp_secret_backend, terraform_cloud_secret_backend, kv_secret_v2).
	// ensure password_wo_version is updated in state

	for _, k := range staticRoleFields {
		if v, ok := role.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return nil
}

func databaseSecretBackendStaticRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Deleting static role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting static role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted static role %q", path)
	return nil
}

func databaseSecretBackendStaticRolePath(backend, name string) string {
	return strings.Trim(backend, "/") + "/static-roles/" + strings.Trim(name, "/")
}

func databaseSecretBackendStaticRoleNameFromPath(path string) (string, error) {
	if !databaseSecretBackendStaticRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := databaseSecretBackendStaticRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func databaseSecretBackendStaticRoleBackendFromPath(path string) (string, error) {
	if !databaseSecretBackendStaticRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := databaseSecretBackendStaticRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func validatePasswordFields(ctx context.Context, d *schema.ResourceDiff, meta interface{}) error {
	// Validate that password_wo and self_managed_password are not both set
	// Use GetRawConfig for write-only field password_wo
	pwWo := d.GetRawConfig().GetAttr(consts.FieldPasswordWO)
	hasPasswordWO := pwWo.IsKnown() && !pwWo.IsNull()
	_, hasSelfManagedPassword := d.GetOk(consts.FieldSelfManagedPassword)

	if hasPasswordWO && hasSelfManagedPassword {
		return fmt.Errorf("password_wo and self_managed_password cannot be used together")
	}
	return nil
}
