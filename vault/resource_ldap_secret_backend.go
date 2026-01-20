// Copyright (c) HashiCorp, Inc.
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

func ldapSecretBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldPath: {
			Type:         schema.TypeString,
			Default:      consts.MountTypeLDAP,
			Optional:     true,
			Description:  "The path where the LDAP secrets backend is mounted.",
			ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
		},
		consts.FieldBindDN: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Distinguished name of object to bind when performing user and group search.",
		},
		consts.FieldBindPass: {
			Type:          schema.TypeString,
			Optional:      true,
			Sensitive:     true,
			Description:   "LDAP password for searching for the user DN.",
			ConflictsWith: []string{consts.FieldBindPassWO},
			ExactlyOneOf:  []string{consts.FieldBindPass, consts.FieldBindPassWO},
		},
		consts.FieldBindPassWO: {
			Type:          schema.TypeString,
			Optional:      true,
			Sensitive:     true,
			WriteOnly:     true,
			Description:   "Write-only LDAP password for searching for the user DN.",
			ConflictsWith: []string{consts.FieldBindPass},
			ExactlyOneOf:  []string{consts.FieldBindPass, consts.FieldBindPassWO},
		},
		consts.FieldBindPassWOVersion: {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  "Version counter for write-only bind password.",
			RequiredWith: []string{consts.FieldBindPassWO},
		},
		consts.FieldCertificate: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "CA certificate to use when verifying LDAP server certificate, must be x509 PEM encoded.",
		},
		consts.FieldClientTLSCert: {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: "Client certificate to provide to the LDAP server, must be x509 PEM encoded.",
		},
		consts.FieldClientTLSKey: {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: "Client certificate key to provide to the LDAP server, must be x509 PEM encoded.",
		},
		consts.FieldInsecureTLS: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Skip LDAP server SSL Certificate verification - insecure and not recommended for production use.",
		},
		consts.FieldPasswordPolicy: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Name of the password policy to use to generate passwords.",
		},
		consts.FieldSchema: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "The LDAP schema to use when storing entry passwords. Valid schemas include openldap, ad, and racf.",
		},
		consts.FieldConnectionTimeout: {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     30,
			Description: "Timeout, in seconds, when attempting to connect to the LDAP server before trying the next URL in the configuration.",
		},
		consts.FieldRequestTimeout: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Timeout, in seconds, for the connection when making requests against the server before returning back an error.",
		},
		consts.FieldStartTLS: {
			Type:        schema.TypeBool,
			Optional:    true,
			Computed:    true,
			Description: "Issue a StartTLS command after establishing unencrypted connection.",
		},
		consts.FieldUPNDomain: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "Enables userPrincipalDomain login with [username]@UPNDomain.",
		},
		consts.FieldURL: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "LDAP URL to connect to (default: ldap://127.0.0.1). Multiple URLs can be specified by concatenating them with commas; they will be tried in-order.",
		},
		consts.FieldUserAttr: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "Attribute used for users (default: cn)",
		},
		consts.FieldUserDN: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "LDAP domain to use for users (eg: ou=People,dc=example,dc=org)",
		},
		consts.FieldSkipStaticRoleImportRotation: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Skip rotation of static role secrets on import.",
		},
		consts.FieldCredentialType: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "The type of credential to manage. Options include: 'password', 'phrase'. Defaults to 'password'.",
		},
	}
	resource := provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(createUpdateLDAPConfigResource, provider.VaultVersion112),
		UpdateContext: createUpdateLDAPConfigResource,
		ReadContext:   provider.ReadContextWrapper(readLDAPConfigResource),
		DeleteContext: deleteLDAPConfigResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Schema:        fields,
	}, false)

	// Add common mount schema to the resource
	provider.MustAddSchema(resource, getMountSchema("path", "type"))

	// add automated rotation fields to the resource
	provider.MustAddSchema(resource, provider.GetAutomatedRootRotationSchema())

	return resource
}

func createUpdateLDAPConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Get(consts.FieldPath).(string)
	log.Printf("[DEBUG] Mounting LDAP mount at %q", path)
	if d.IsNewResource() {
		if err := createMount(ctx, d, meta, client, path, consts.MountTypeLDAP); err != nil {
			return diag.FromErr(err)
		}
	} else {
		if err := updateMount(ctx, d, meta, true, false); err != nil {
			return diag.FromErr(err)
		}
	}

	log.Printf("[DEBUG] Mounted LDAP mount at %q", path)
	d.SetId(path)

	data := map[string]interface{}{}
	fields := []string{
		consts.FieldBindDN,
		consts.FieldBindPass,
		consts.FieldCertificate,
		consts.FieldConnectionTimeout,
		consts.FieldClientTLSCert,
		consts.FieldClientTLSKey,
		consts.FieldPasswordPolicy,
		consts.FieldRequestTimeout,
		consts.FieldSchema,
		consts.FieldUPNDomain,
		consts.FieldURL,
		consts.FieldUserAttr,
		consts.FieldUserDN,
	}

	if provider.IsAPISupported(meta, provider.VaultVersion118) {
		fields = append(fields, consts.FieldCredentialType)
	}

	booleanFields := []string{
		consts.FieldInsecureTLS,
		consts.FieldStartTLS,
	}

	// add skip_static_role_import_rotation if after vault 1.16
	if provider.IsAPISupported(meta, provider.VaultVersion116) {
		booleanFields = append(booleanFields, consts.FieldSkipStaticRoleImportRotation)
	}

	// use d.Get() for boolean fields
	for _, field := range booleanFields {
		data[field] = d.Get(field)
	}

	for _, field := range fields {
		// don't update bindpass unless it was changed in the config so that we
		// don't overwrite it in the event a rotate-root operation was
		// performed in Vault
		if field == consts.FieldBindPass && !d.HasChange(field) {
			continue
		}

		if v, ok := d.GetOk(field); ok {
			data[field] = v
		}
	}

	// Handle write-only bindpass field
	if _, hasBindPass := data[consts.FieldBindPass]; !hasBindPass {
		if d.IsNewResource() || d.HasChange(consts.FieldBindPassWOVersion) {
			p := cty.GetAttrPath(consts.FieldBindPassWO)
			woVal, _ := d.GetRawConfigAt(p)
			if !woVal.IsNull() {
				data[consts.FieldBindPass] = woVal.AsString()
			}
		}
	}

	// get automated rotation fields
	if provider.IsAPISupported(meta, provider.VaultVersion119) && provider.IsEnterpriseSupported(meta) {
		automatedrotationutil.ParseAutomatedRotationFields(d, data)
	}

	configPath := fmt.Sprintf("%s/config", path)
	log.Printf("[DEBUG] Writing %q", configPath)
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return diag.FromErr(fmt.Errorf("error writing %q: %s", configPath, err))
	}
	log.Printf("[DEBUG] Wrote %q", configPath)
	return readLDAPConfigResource(ctx, d, meta)
}

func readLDAPConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()
	configPath := fmt.Sprintf("%s/config", path)
	log.Printf("[DEBUG] Reading %q", configPath)

	resp, err := client.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading %q: %s", configPath, err))
	}
	log.Printf("[DEBUG] Read %q", configPath)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", configPath)
		d.SetId("")
		return nil
	}

	fields := []string{
		consts.FieldBindDN,
		consts.FieldConnectionTimeout,
		consts.FieldClientTLSCert,
		consts.FieldClientTLSKey,
		consts.FieldInsecureTLS,
		consts.FieldPasswordPolicy,
		consts.FieldRequestTimeout,
		consts.FieldSchema,
		consts.FieldStartTLS,
		consts.FieldUPNDomain,
		consts.FieldURL,
		consts.FieldUserAttr,
		consts.FieldUserDN,
	}
	if provider.IsAPISupported(meta, provider.VaultVersion116) {
		fields = append(fields, consts.FieldSkipStaticRoleImportRotation)
	}
	if provider.IsAPISupported(meta, provider.VaultVersion118) {
		fields = append(fields, consts.FieldCredentialType)
	}

	for _, field := range fields {
		if val, ok := resp.Data[field]; ok {
			if err := d.Set(field, val); err != nil {
				return diag.FromErr(fmt.Errorf("error setting state key '%s': %s", field, err))
			}
		}
	}

	if err := readMount(ctx, d, meta, true, false); err != nil {
		return diag.FromErr(err)
	}

	// add automated rotation fields automatically
	if provider.IsAPISupported(meta, provider.VaultVersion119) && provider.IsEnterpriseSupported(meta) {
		if err := automatedrotationutil.PopulateAutomatedRotationFields(d, resp, path); err != nil {
			return diag.Errorf("error setting automated rotation fields: %s", err)
		}
	}

	return nil
}

func deleteLDAPConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	vaultPath := d.Id()
	log.Printf("[DEBUG] Unmounting LDAP backend %q", vaultPath)

	err = client.Sys().UnmountWithContext(ctx, vaultPath)
	if err != nil {
		if util.Is404(err) {
			log.Printf("[WARN] %q not found, removing from state", vaultPath)
			d.SetId("")
			return nil
		}
		return diag.FromErr(fmt.Errorf("error unmounting LDAP backend from %q: %s", vaultPath, err))
	}
	log.Printf("[DEBUG] Unmounted LDAP backend %q", vaultPath)
	return nil
}
