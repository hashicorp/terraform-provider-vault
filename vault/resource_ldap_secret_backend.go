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
	"github.com/hashicorp/vault/api"
	"log"
)

func ldapSecretBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldBackend: {
			Type:         schema.TypeString,
			Default:      consts.MountTypeLDAP,
			Optional:     true,
			Description:  `The mount path for a backend, for example, the path given in "$ vault secrets enable -path=my-ldap openldap".`,
			ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
		},
		"binddn": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `Distinguished name of object to bind when performing user and group search.`,
		},
		"bindpass": {
			Type:        schema.TypeString,
			Required:    true,
			Sensitive:   true,
			Description: `LDAP password for searching for the user DN.`,
		},
		"case_sensitive_names": {
			Type:        schema.TypeBool,
			Computed:    true,
			Description: `If true, case sensitivity will be used when comparing usernames and groups for matching policies.`,
		},
		"certificate": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `CA certificate to use when verifying LDAP server certificate, must be x509 PEM encoded.`,
		},
		"client_tls_cert": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: `Client certificate to provide to the LDAP server, must be x509 PEM encoded.`,
		},
		"client_tls_key": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: `Client certificate key to provide to the LDAP server, must be x509 PEM encoded.`,
		},
		consts.FieldDefaultLeaseTTL: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Default lease duration for secrets in seconds",
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Human-friendly description of the mount for the backend.",
		},
		"insecure_tls": {
			Type:        schema.TypeBool,
			Optional:    true,
			Computed:    true,
			Description: `Skip LDAP server SSL Certificate verification - insecure and not recommended for production use.`,
		},
		"length": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Deprecated:  `Length is deprecated and password_policy should be used with Vault >= 1.5.`,
			Description: `The desired length of passwords that Vault generates.`,
		},
		consts.FieldMaxLeaseTTL: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
		"max_ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `In seconds, the maximum password time-to-live.`,
		},
		"password_policy": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Name of the password policy to use to generate passwords.`,
		},
		"schema": {
			Type:        schema.TypeString,
			Default:     "openldap",
			Optional:    true,
			Description: `The LDAP schema to use when storing entry passwords. Valid schemas include openldap, ad, and racf.`,
		},
		"request_timeout": {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     90,
			Description: `Timeout, in seconds, for the connection when making requests against the server before returning back an error.`,
		},
		"starttls": {
			Type:        schema.TypeBool,
			Optional:    true,
			Computed:    true,
			Description: `Issue a StartTLS command after establishing unencrypted connection.`,
		},
		"tls_max_version": {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: `Maximum TLS version to use. Accepted values are 'tls10', 'tls11', 'tls12' or 'tls13'. Defaults to 'tls12'`,
		},
		"tls_min_version": {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: `Minimum TLS version to use. Accepted values are 'tls10', 'tls11', 'tls12' or 'tls13'. Defaults to 'tls12'`,
		},
		consts.FieldTTL: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `In seconds, the default password time-to-live.`,
		},
		"upndomain": {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: `Enables userPrincipalDomain login with [username]@UPNDomain.`,
		},
		"url": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `LDAP URL to connect to (default: ldap://127.0.0.1). Multiple URLs can be specified by concatenating them with commas; they will be tried in-order.`,
		},
		"userattr": {
			Type:        schema.TypeString,
			Default:     "cn",
			Optional:    true,
			Description: `Attribute used for users (default: cn)`,
		},
		"userdn": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `LDAP domain to use for users (eg: ou=People,dc=example,dc=org)`,
		},
	}
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: createLDAPConfigResource,
		UpdateContext: updateLDAPConfigResource,
		ReadContext:   ReadContextWrapper(readLDAPConfigResource),
		DeleteContext: deleteLDAPConfigResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldBackend),
		Schema:        fields,
	})
}

func createLDAPConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	description := d.Get("description").(string)
	defaultTTL := d.Get(consts.FieldDefaultLeaseTTL).(int)
	maxTTL := d.Get(consts.FieldMaxLeaseTTL).(int)

	log.Printf("[DEBUG] Mounting LDAP backend at %q", backend)
	err = client.Sys().Mount(backend, &api.MountInput{
		Type:        consts.MountTypeLDAP,
		Description: description,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
			MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
		},
	})
	if err != nil {
		return diag.FromErr(fmt.Errorf("error mounting to %q: %s", backend, err))
	}

	log.Printf("[DEBUG] Mounted LDAP backend at %q", backend)
	d.SetId(backend)

	data := map[string]interface{}{}
	if v, ok := d.GetOk("binddn"); ok {
		data["binddn"] = v
	}
	if v, ok := d.GetOk("bindpass"); ok {
		data["bindpass"] = v
	}
	if v, ok := d.GetOk("case_sensitive_names"); ok {
		data["case_sensitive_names"] = v
	}
	if v, ok := d.GetOk("certificate"); ok {
		data["certificate"] = v
	}
	if v, ok := d.GetOk("client_tls_cert"); ok {
		data["client_tls_cert"] = v
	}
	if v, ok := d.GetOk("client_tls_key"); ok {
		data["client_tls_key"] = v
	}
	if v, ok := d.GetOk("groupdn"); ok {
		data["groupdn"] = v
	}
	if v, ok := d.GetOk("insecure_tls"); ok {
		data["insecure_tls"] = v
	}
	if v, ok := d.GetOk("last_rotation_tolerance"); ok {
		data["last_rotation_tolerance"] = v
	}
	if v, ok := d.GetOk("length"); ok {
		data["length"] = v
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v
	}
	if v, ok := d.GetOk("password_policy"); ok {
		data["password_policy"] = v
	}
	if v, ok := d.GetOk("request_timeout"); ok {
		data["request_timeout"] = v
	}
	if v, ok := d.GetOk("starttls"); ok {
		data["starttls"] = v
	}
	if v, ok := d.GetOk("tls_max_version"); ok {
		data["tls_max_version"] = v
	}
	if v, ok := d.GetOk("tls_min_version"); ok {
		data["tls_min_version"] = v
	}
	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v
	}
	if v, ok := d.GetOk("upndomain"); ok {
		data["upndomain"] = v
	}
	if v, ok := d.GetOk("url"); ok {
		data["url"] = v
	}
	if v, ok := d.GetOk("use_token_groups"); ok {
		data["use_token_groups"] = v
	}
	if v, ok := d.GetOk("userattr"); ok {
		data["userattr"] = v
	}
	if v, ok := d.GetOk("userdn"); ok {
		data["userdn"] = v
	}

	configPath := fmt.Sprintf("%s/config", backend)
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
	log.Printf("[DEBUG] Reading %q", path)

	mountResp, err := client.Sys().MountConfig(path)
	if err != nil && util.Is404(err) {
		log.Printf("[WARN] %q not found, removing from state", path)
		d.SetId("")
		return nil
	} else if err != nil {
		return diag.FromErr(fmt.Errorf("error reading %q: %s", path, err))
	}

	d.Set(consts.FieldBackend, d.Id())

	d.Set(consts.FieldDefaultLeaseTTL, mountResp.DefaultLeaseTTL)
	d.Set(consts.FieldMaxLeaseTTL, mountResp.MaxLeaseTTL)

	configPath := fmt.Sprintf("%s/config", d.Id())
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

	if val, ok := resp.Data["binddn"]; ok {
		if err := d.Set("binddn", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'binddn': %s", err))
		}
	}
	if val, ok := resp.Data["case_sensitive_names"]; ok {
		if err := d.Set("case_sensitive_names", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'case_sensitive_names': %s", err))
		}
	}
	if val, ok := resp.Data["client_tls_cert"]; ok {
		if err := d.Set("client_tls_cert", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'client_tls_cert': %s", err))
		}
	}
	if val, ok := resp.Data["client_tls_key"]; ok {
		if err := d.Set("client_tls_key", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'client_tls_key': %s", err))
		}
	}
	if val, ok := resp.Data["insecure_tls"]; ok {
		if err := d.Set("insecure_tls", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'insecure_tls': %s", err))
		}
	}
	if val, ok := resp.Data["length"]; ok {
		if err := d.Set("length", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'length': %s", err))
		}
	}
	if val, ok := resp.Data["max_ttl"]; ok {
		if err := d.Set("max_ttl", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'max_ttl': %s", err))
		}
	}
	if val, ok := resp.Data["password_policy"]; ok {
		if err := d.Set("password_policy", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'password_policy': %s", err))
		}
	}
	if val, ok := resp.Data["request_timeout"]; ok {
		if err := d.Set("request_timeout", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'request_timeout': %s", err))
		}
	}
	if val, ok := resp.Data["starttls"]; ok {
		if err := d.Set("starttls", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'starttls': %s", err))
		}
	}
	if val, ok := resp.Data["tls_max_version"]; ok {
		if err := d.Set("tls_max_version", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'tls_max_version': %s", err))
		}
	}
	if val, ok := resp.Data["tls_min_version"]; ok {
		if err := d.Set("tls_min_version", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'tls_min_version': %s", err))
		}
	}
	if val, ok := resp.Data["ttl"]; ok {
		if err := d.Set("ttl", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'ttl': %s", err))
		}
	}
	if val, ok := resp.Data["upndomain"]; ok {
		if err := d.Set("upndomain", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'upndomain': %s", err))
		}
	}
	if val, ok := resp.Data["url"]; ok {
		if err := d.Set("url", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'url': %s", err))
		}
	}
	if val, ok := resp.Data["userattr"]; ok {
		if err := d.Set("userattr", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'userattr': %s", err))
		}
	}
	if val, ok := resp.Data["userdn"]; ok {
		if err := d.Set("userdn", val); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'userdn': %s", err))
		}
	}
	return nil
}

func updateLDAPConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	backend := d.Id()

	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend, err = util.Remount(d, client, consts.FieldBackend, false)
	if err != nil {
		return diag.FromErr(err)
	}

	defaultTTL := d.Get(consts.FieldDefaultLeaseTTL).(int)
	maxTTL := d.Get(consts.FieldMaxLeaseTTL).(int)
	tune := api.MountConfigInput{}
	data := map[string]interface{}{}

	if defaultTTL != 0 {
		tune.DefaultLeaseTTL = fmt.Sprintf("%ds", defaultTTL)
		data[consts.FieldDefaultLeaseTTL] = defaultTTL
	}

	if maxTTL != 0 {
		tune.MaxLeaseTTL = fmt.Sprintf("%ds", maxTTL)
		data[consts.FieldMaxLeaseTTL] = maxTTL
	}

	if tune.DefaultLeaseTTL != "0" || tune.MaxLeaseTTL != "0" {
		err := client.Sys().TuneMount(backend, tune)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error mounting to %q: %s", backend, err))
		}
	}

	vaultPath := fmt.Sprintf("%s/config", backend)
	log.Printf("[DEBUG] Updating %q", vaultPath)

	if raw, ok := d.GetOk("binddn"); ok {
		data["binddn"] = raw
	}
	if raw, ok := d.GetOk("bindpass"); ok {
		data["bindpass"] = raw
	}
	if raw, ok := d.GetOk("case_sensitive_names"); ok {
		data["case_sensitive_names"] = raw
	}
	if raw, ok := d.GetOk("certificate"); ok {
		data["certificate"] = raw
	}
	if raw, ok := d.GetOk("client_tls_cert"); ok {
		data["client_tls_cert"] = raw
	}
	if raw, ok := d.GetOk("client_tls_key"); ok {
		data["client_tls_key"] = raw
	}
	if raw, ok := d.GetOk("groupfilter"); ok {
		data["groupfilter"] = raw
	}
	if raw, ok := d.GetOk("insecure_tls"); ok {
		data["insecure_tls"] = raw
	}
	if raw, ok := d.GetOk("length"); ok {
		data["length"] = raw
	}
	if raw, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = raw
	}
	if raw, ok := d.GetOk("password_policy"); ok {
		data["password_policy"] = raw
	}
	if raw, ok := d.GetOk("request_timeout"); ok {
		data["request_timeout"] = raw
	}
	if raw, ok := d.GetOk("starttls"); ok {
		data["starttls"] = raw
	}
	if raw, ok := d.GetOk("tls_max_version"); ok {
		data["tls_max_version"] = raw
	}
	if raw, ok := d.GetOk("tls_min_version"); ok {
		data["tls_min_version"] = raw
	}
	if raw, ok := d.GetOk("ttl"); ok {
		data["ttl"] = raw
	}
	if raw, ok := d.GetOk("upndomain"); ok {
		data["upndomain"] = raw
	}
	if raw, ok := d.GetOk("url"); ok {
		data["url"] = raw
	}
	if raw, ok := d.GetOk("use_pre111_group_cn_behavior"); ok {
		data["use_pre111_group_cn_behavior"] = raw
	}
	if raw, ok := d.GetOk("userattr"); ok {
		data["userattr"] = raw
	}
	if raw, ok := d.GetOk("userdn"); ok {
		data["userdn"] = raw
	}
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return diag.FromErr(fmt.Errorf("error updating template auth backend role %q: %s", vaultPath, err))
	}
	log.Printf("[DEBUG] Updated %q", vaultPath)
	return readLDAPConfigResource(ctx, d, meta)
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
