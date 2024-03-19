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

func ldapAuthBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"url": {
			Type:     schema.TypeString,
			Required: true,
		},
		"starttls": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"tls_min_version": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"tls_max_version": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"insecure_tls": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"certificate": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"binddn": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"bindpass": {
			Type:      schema.TypeString,
			Optional:  true,
			Computed:  true,
			Sensitive: true,
		},
		"case_sensitive_names": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"max_page_size": {
			Type:     schema.TypeInt,
			Default:  -1,
			Optional: true,
		},
		"userdn": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"userattr": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
			StateFunc: func(v interface{}) string {
				return strings.ToLower(v.(string))
			},
		},
		"userfilter": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"discoverdn": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"deny_null_bind": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"upndomain": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"groupfilter": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"groupdn": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"groupattr": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"username_as_alias": {
			Type:        schema.TypeBool,
			Optional:    true,
			Computed:    true,
			Description: "Force the auth method to use the username passed by the user as the alias name.",
		},
		"use_token_groups": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},

		"description": {
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
		"local": {
			Type:        schema.TypeBool,
			ForceNew:    true,
			Optional:    true,
			Default:     false,
			Description: "Specifies if the auth method is local only",
		},
		"accessor": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "The accessor of the LDAP auth backend",
		},
		"client_tls_cert": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"client_tls_key": {
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

	if v, ok := d.GetOk("description"); ok {
		data["description"] = v.(string)
	}

	if v, ok := d.GetOk("url"); ok {
		data["url"] = v.(string)
	}

	if v, ok := d.GetOkExists("starttls"); ok {
		data["starttls"] = v.(bool)
	}

	if v, ok := d.GetOk("tls_min_version"); ok {
		data["tls_min_version"] = v.(string)
	}

	if v, ok := d.GetOk("tls_max_version"); ok {
		data["tls_max_version"] = v.(string)
	}

	if v, ok := d.GetOkExists("insecure_tls"); ok {
		data["insecure_tls"] = v.(bool)
	}

	if v, ok := d.GetOk("certificate"); ok {
		data["certificate"] = v.(string)
	}

	if v, ok := d.GetOk("binddn"); ok {
		data["binddn"] = v.(string)
	}

	if v, ok := d.GetOk("bindpass"); ok {
		data["bindpass"] = v.(string)
	}

	if v, ok := d.GetOkExists("case_sensitive_names"); ok {
		data["case_sensitive_names"] = v.(bool)
	}

	if v, ok := d.GetOkExists("max_page_size"); ok {
		data["max_page_size"] = v
	}

	if v, ok := d.GetOk("userdn"); ok {
		data["userdn"] = v.(string)
	}

	if v, ok := d.GetOk("userattr"); ok {
		data["userattr"] = v.(string)
	}

	if v, ok := d.GetOk("userfilter"); ok {
		data["userfilter"] = v.(string)
	}

	if v, ok := d.GetOkExists("discoverdn"); ok {
		data["discoverdn"] = v.(bool)
	}

	if v, ok := d.GetOkExists("deny_null_bind"); ok {
		data["deny_null_bind"] = v.(bool)
	}

	if v, ok := d.GetOk("upndomain"); ok {
		data["upndomain"] = v.(string)
	}

	if v, ok := d.GetOk("groupfilter"); ok {
		data["groupfilter"] = v.(string)
	}

	if v, ok := d.GetOk("groupdn"); ok {
		data["groupdn"] = v.(string)
	}

	if v, ok := d.GetOk("groupattr"); ok {
		data["groupattr"] = v.(string)
	}

	if v, ok := d.GetOkExists("username_as_alias"); ok {
		data["username_as_alias"] = v.(bool)
	}

	if v, ok := d.GetOkExists("use_token_groups"); ok {
		data["use_token_groups"] = v.(bool)
	}

	if v, ok := d.GetOk("client_tls_cert"); ok {
		data["client_tls_cert"] = v.(string)
	}

	if v, ok := d.GetOk("client_tls_key"); ok {
		data["client_tls_key"] = v.(string)
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

	d.Set("path", path)
	d.Set("description", authMount.Description)
	d.Set("accessor", authMount.Accessor)
	d.Set("local", authMount.Local)

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

	d.Set("url", resp.Data["url"])
	d.Set("starttls", resp.Data["starttls"])
	d.Set("tls_min_version", resp.Data["tls_min_version"])
	d.Set("tls_max_version", resp.Data["tls_max_version"])
	d.Set("insecure_tls", resp.Data["insecure_tls"])
	d.Set("certificate", resp.Data["certificate"])
	d.Set("binddn", resp.Data["binddn"])
	d.Set("case_sensitive_names", resp.Data["case_sensitive_names"])
	d.Set("max_page_size", resp.Data["max_page_size"])
	d.Set("userdn", resp.Data["userdn"])
	d.Set("userattr", resp.Data["userattr"])
	d.Set("userfilter", resp.Data["userfilter"])
	d.Set("discoverdn", resp.Data["discoverdn"])
	d.Set("deny_null_bind", resp.Data["deny_null_bind"])
	d.Set("upndomain", resp.Data["upndomain"])
	d.Set("groupfilter", resp.Data["groupfilter"])
	d.Set("groupdn", resp.Data["groupdn"])
	d.Set("groupattr", resp.Data["groupattr"])
	d.Set("username_as_alias", resp.Data["username_as_alias"])
	d.Set("use_token_groups", resp.Data["use_token_groups"])

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
