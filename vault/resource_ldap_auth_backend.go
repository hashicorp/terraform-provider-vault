// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

const ldapAuthType string = "ldap"

var ldapAuthBackendFields = []string{
	consts.FieldURL,
	consts.FieldTLSMinVersion,
	consts.FieldTLSMaxVersion,
	consts.FieldCertificate,
	consts.FieldBindDN,
	consts.FieldUserDN,
	consts.FieldUserAttr,
	consts.FieldUserFilter,
	consts.FieldUPNDomain,
	consts.FieldGroupFilter,
	consts.FieldGroupDN,
	consts.FieldGroupAttr,
}

var ldapAuthBackendBooleanFields = []string{
	consts.FieldStartTLS,
	consts.FieldInsecureTLS,
	consts.FieldCaseSensitiveNames,
	consts.FieldDiscoverDN,
	consts.FieldDenyNullBind,
	consts.FieldUsernameAsAlias,
	consts.FieldUseTokenGroups,
}

func ldapAuthBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldURL: {
			Type:     schema.TypeString,
			Required: true,
		},
		consts.FieldStartTLS: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		consts.FieldTLSMinVersion: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldTLSMaxVersion: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldInsecureTLS: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		consts.FieldCertificate: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldBindDN: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldBindPass: {
			Type:      schema.TypeString,
			Optional:  true,
			Computed:  true,
			Sensitive: true,
		},
		consts.FieldCaseSensitiveNames: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		consts.FieldMaxPageSize: {
			Type:     schema.TypeInt,
			Default:  -1,
			Optional: true,
		},
		consts.FieldUserDN: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldUserAttr: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
			StateFunc: func(v interface{}) string {
				return strings.ToLower(v.(string))
			},
		},
		consts.FieldUserFilter: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldDiscoverDN: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		consts.FieldDenyNullBind: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		consts.FieldUPNDomain: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldGroupFilter: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldGroupDN: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldGroupAttr: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldUsernameAsAlias: {
			Type:        schema.TypeBool,
			Optional:    true,
			Computed:    true,
			Description: "Force the auth method to use the username passed by the user as the alias name.",
		},
		consts.FieldUseTokenGroups: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		consts.FieldDescription: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldPath: {
			Type:     schema.TypeString,
			Optional: true,
			Default:  "ldap",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		consts.FieldLocal: {
			Type:        schema.TypeBool,
			ForceNew:    true,
			Optional:    true,
			Default:     false,
			Description: "Specifies if the auth method is local only",
		},
		consts.FieldAccessor: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "The accessor of the LDAP auth backend",
		},
		consts.FieldClientTLSCert: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldClientTLSKey: {
			Type:      schema.TypeString,
			Optional:  true,
			Computed:  true,
			Sensitive: true,
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return provider.MustAddMountMigrationSchema(&schema.Resource{
		SchemaVersion: 2,
		// Handle custom state upgrade case since schema version was already 1
		StateUpgraders: []schema.StateUpgrader{
			{
				Version: 1,
				Type:    provider.SecretsAuthMountDisableRemountResourceV0().CoreConfigSchema().ImpliedType(),
				Upgrade: provider.SecretsAuthMountDisableRemountUpgradeV0,
			},
		},
		CreateContext: ldapAuthBackendWrite,
		UpdateContext: ldapAuthBackendUpdate,
		ReadContext:   provider.ReadContextWrapper(ldapAuthBackendRead),
		DeleteContext: ldapAuthBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Schema:        fields,
	}, true)
}

func ldapAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}

func ldapAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get("path").(string)
	options := &api.EnableAuthOptions{
		Type:        ldapAuthType,
		Description: d.Get("description").(string),
		Local:       d.Get("local").(bool),
	}

	log.Printf("[DEBUG] Enabling LDAP auth backend %q", path)
	err := client.Sys().EnableAuthWithOptions(path, options)
	if err != nil {
		return diag.Errorf("error enabling ldap auth backend %q: %s", path, err)
	}
	log.Printf("[DEBUG] Enabled LDAP auth backend %q", path)

	d.SetId(path)

	return ldapAuthBackendUpdate(ctx, d, meta)
}

func ldapAuthBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := ldapAuthBackendConfigPath(d.Id())

	if !d.IsNewResource() {
		newMount, err := util.Remount(d, client, consts.FieldPath, true)
		if err != nil {
			return diag.FromErr(err)
		}

		path = ldapAuthBackendConfigPath(newMount)
	}

	data := map[string]interface{}{}

	for _, k := range ldapAuthBackendFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v.(string)
		}
	}

	// handle boolean fields
	for _, k := range ldapAuthBackendBooleanFields {
		data[k] = d.Get(k)
	}

	useAPIVer111 := provider.IsAPISupported(meta, provider.VaultVersion111)
	if useAPIVer111 {
		if v, ok := d.GetOk(consts.FieldMaxPageSize); ok {
			data[consts.FieldMaxPageSize] = v
		}
	}

	if v, ok := d.GetOk(consts.FieldBindPass); ok {
		data[consts.FieldBindPass] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldClientTLSCert); ok {
		data[consts.FieldClientTLSCert] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldClientTLSKey); ok {
		data[consts.FieldClientTLSKey] = v.(string)
	}

	updateTokenFields(d, data, false)

	log.Printf("[DEBUG] Writing LDAP config %q", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("error writing ldap config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote LDAP config %q", path)

	return ldapAuthBackendRead(ctx, d, meta)
}

func ldapAuthBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	authMount, err := mountutil.GetAuthMount(ctx, client, path)
	if errors.Is(err, mountutil.ErrMountNotFound) {
		log.Printf("[WARN] Mount %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	if err != nil {
		return diag.FromErr(err)
	}

	d.Set(consts.FieldPath, path)
	d.Set(consts.FieldDescription, authMount.Description)
	d.Set(consts.FieldAccessor, authMount.Accessor)
	d.Set(consts.FieldLocal, authMount.Local)

	path = ldapAuthBackendConfigPath(path)

	log.Printf("[DEBUG] Reading LDAP auth backend config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading ldap auth backend config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read LDAP auth backend config %q", path)

	if resp == nil {
		log.Printf("[WARN] LDAP auth backend config %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range ldapAuthBackendFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error reading %s for LDAP Auth Backend Role %q: %q", k, path, err)
			}
		}
	}

	// handle TypeBool
	for _, k := range ldapAuthBackendBooleanFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error reading %s for LDAP Auth Backend Role %q: %q", k, path, err)
			}
		}
	}

	useAPIVer111 := provider.IsAPISupported(meta, provider.VaultVersion111)
	if useAPIVer111 {
		if err := d.Set(consts.FieldMaxPageSize, resp.Data[consts.FieldMaxPageSize]); err != nil {
			return diag.Errorf("error reading %s for LDAP Auth Backend %q: %q", consts.FieldMaxPageSize, path, err)
		}
	}

	// `bindpass`, `client_tls_cert` and `client_tls_key` cannot be read out from the API
	// So... if they drift, they drift.

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func ldapAuthBackendDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting LDAP auth backend %q", path)
	err := client.Sys().DisableAuth(path)
	if err != nil {
		return diag.Errorf("error deleting ldap auth backend %q: %q", path, err)
	}
	log.Printf("[DEBUG] Deleted LDAP auth backend %q", path)

	return nil
}
