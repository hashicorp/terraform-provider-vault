// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/vault/api"
)

func ldapSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: ldapSecretBackendCreate,
		UpdateContext: ldapSecretBackendUpdate,
		ReadContext:   ReadContextWrapper(ldapSecretBackendRead),
		DeleteContext: deleteLdapSecretBackend,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Default:     consts.MountTypeLDAP,
				Optional:    true,
				ForceNew:    true,
				Description: `The mount path for a backend, for example, the path given in "$ vault auth enable -path=ldap ldap".`,
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"anonymous_group_search": {
				Type:        schema.TypeBool,
				Computed:    true,
				Optional:    true,
				Description: `Use anonymous binds when performing LDAP group searches (if true the initial credentials will still be used for the initial connection test).`,
			},
			"binddn": {
				Type:        schema.TypeString,
				Required:    true,
				Description: `Distinguished name (DN) of object to bind for managing user entries. For example, cn=vault,ou=Users,dc=hashicorp,dc=com.`,
			},
			"bindpass": {
				Type:        schema.TypeString,
				Computed:    false,
				Required:    true,
				Sensitive:   true,
				Description: `Password to use along with binddn for managing user entries.`,
			},
			"case_sensitive_names": {
				Type:        schema.TypeBool,
				Computed:    true,
				Optional:    true,
				Description: `If true, case sensitivity will be used when comparing usernames and groups for matching policies.`,
			},
			"certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `CA certificate to use when verifying LDAP server certificate, must be x509 PEM encoded.`,
			},
			"deny_null_bind": {
				Type:        schema.TypeBool,
				Computed:    true,
				Optional:    true,
				Description: `Denies an unauthenticated LDAP bind request if the user's password is empty.`,
			},
			"discoverdn": {
				Type:        schema.TypeBool,
				Computed:    true,
				Optional:    true,
				Description: `Use anonymous bind to discover the bind DN of a user.`,
			},
			"groupattr": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: `The attribute field name used to perform group search in library management and static roles.`,
			},
			"groupdn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The base DN under which to perform group search in library management and static roles.`,
			},
			"groupfilter": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: `Go template for querying group membership of user.`,
			},
			"insecure_tls": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: `If true, skips LDAP server SSL certificate verification - insecure, use with caution!`,
			},
			"request_timeout": {
				Type:        schema.TypeInt,
				Computed:    true,
				Optional:    true,
				Description: `Timeout, in seconds, for the connection when making requests against the server before returning back an error.`,
			},
			"schema": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  `The LDAP schema to use when storing entry passwords. Valid schemas include openldap, ad, and racf.`,
				ValidateFunc: validation.StringInSlice([]string{"tls10", "tls11", "tls12", "tls13"}, false),
			},
			"starttls": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: `If true, issues a StartTLS command after establishing an unencrypted connection.`,
			},
			"upndomain": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: ` The domain (userPrincipalDomain) used to construct a UPN string for authentication.`,
			},
			"url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: `Password to use along with binddn for managing user entries.`,
			},
			"use_token_groups": {
				Type:        schema.TypeBool,
				Computed:    true,
				Optional:    true,
				Description: `If true, use the Active Directory tokenGroups constructed attribute of the user to find the group memberships. This will find all security groups including nested ones.`,
			},
			"password_policy": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: `The name of the password policy to use to generate passwords. Note that this accepts the name of the policy, not the policy itself.`,
			},
			"userattr": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: `The attribute field name used to perform user search in library management and static roles.`,
			},
			"userdn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The base DN under which to perform user search in library management and static roles.`,
			},
			"userfilter": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: `Go template for LDAP user search filter`,
			},
			"username_as_alias": {
				Type:        schema.TypeBool,
				Computed:    true,
				Optional:    true,
				Description: `If true, sets the alias name to the username`,
			},

			"tls_min_version": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  `Minimum TLS version to use. Accepted values are 'tls10', 'tls11', 'tls12' or 'tls13'.`,
				ValidateFunc: validation.StringInSlice([]string{"tls10", "tls11", "tls12", "tls13"}, false),
			},
			"tls_max_version": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  `Maximum TLS version to use. Accepted values are 'tls10', 'tls11', 'tls12' or 'tls13'.`,
				ValidateFunc: validation.StringInSlice([]string{"tls10", "tls11", "tls12", "tls13"}, false),
			},

			"connection_timeout": {
				Type:        schema.TypeInt,
				Computed:    true,
				Optional:    true,
				Description: `Timeout, in seconds, when attempting to connect to the LDAP server before trying the next URL in the configuration.`,
			},
			"client_tls_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `Client certificate to provide to the LDAP server, must be x509 PEM encoded.`,
			},
			"client_tls_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `Client key to provide to the LDAP server, must be x509 PEM encoded.`,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `Mount description.`,
			},
			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Default lease duration for secrets in seconds",
			},
			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Maximum possible lease duration for secrets in seconds.",
			},
			"last_bind_password_rotation": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time the bind password was last rotated.",
			},
		},
	}
}

func ldapSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)

	info := &api.MountInput{
		Type:        consts.MountTypeLDAP,
		Description: d.Get("description").(string),
		Local:       false,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		},
	}

	log.Printf("[DEBUG] Mounting LDAP backend at %q", path)
	if err := client.Sys().Mount(path, info); err != nil {
		return diag.FromErr(err)
	}

	data := map[string]interface{}{}
	configFields := []string{
		"anonymous_group_search",
		"binddn",
		"bindpass",
		"case_sensitive_names",
		"certificate",
		"deny_null_bind",
		"discoverdn",
		"groupattr",
		"groupdn",
		"groupfilter",
		"insecure_tls",
		"password_policy",
		"request_timeout",
		"schema",
		"starttls",
		"tls_max_version",
		"tls_min_version",
		"upndomain",
		"url",
		"use_token_groups",
		"userattr",
		"userdn",
		"userfilter",
		"username_as_alias",
	}
	for _, k := range configFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	configPath := path + "/config"
	log.Printf("[DEBUG] Writing LDAP configuration to %q", configPath)

	if _, err := client.Logical().Write(configPath, data); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(path)

	return ldapSecretBackendRead(ctx, d, meta)
}

func ldapSecretBackendRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	diags := diag.Diagnostics{}

	path := d.Id()
	log.Printf("[DEBUG] Reading LDAP backend mount %q from Vault", path)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return diag.Errorf("error reading mount %q: %s", path, err)
	}

	// path can have a trailing slash, but doesn't need to have one
	// this standardises on having a trailing slash, which is how the
	// API always responds.
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	mountConfig, err := client.Sys().MountConfig(path)
	if err != nil {
		return diag.Errorf("error reading config from Vault: %s", err)
	}
	if mountConfig == nil {
		log.Printf("[WARN] config (%s) not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set(consts.FieldPath, d.Id())
	d.Set("description", mount.Description)
	d.Set("default_lease_ttl_seconds", mountConfig.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mountConfig.MaxLeaseTTL)

	configPath := fmt.Sprintf("%s/config", d.Id())
	log.Printf("[DEBUG] Reading %s from Vault", configPath)

	config, err := client.Logical().Read(configPath)
	if err != nil {
		return diag.Errorf("error reading config from mount %q: %s", path, err)
	}
	if config != nil {
		// log.Printf("[WARN] config (%s) not found, removing from state", path)
		// d.SetId("")
		// return nil

		configFields := []string{
			"anonymous_group_search",
			"binddn",
			"case_sensitive_names",
			"certificate",
			"deny_null_bind",
			"discoverdn",
			"groupattr",
			"groupdn",
			"groupfilter",
			"insecure_tls",
			"last_bind_password_rotation",
			"password_policy",
			"request_timeout",
			"schema",
			"starttls",
			"tls_max_version",
			"tls_min_version",
			"upndomain",
			"url",
			"use_token_groups",
			"userattr",
			"userdn",
			"userfilter",
			"username_as_alias",
		}

		for _, k := range configFields {
			if err := d.Set(k, config.Data[k]); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return diags
}

func ldapSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	backend := d.Id()

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	tune := api.MountConfigInput{}

	if d.HasChange("description") {
		description := d.Get("description").(string)
		tune.Description = &description
	}
	if d.HasChange("default_lease_ttl_seconds") {
		tune.DefaultLeaseTTL = fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds").(int))
	}
	if d.HasChange("max_lease_ttl_seconds") {
		tune.MaxLeaseTTL = fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int))
	}

	if d.HasChanges("description", "default_lease_ttl_seconds", "max_lease_ttl_seconds") {
		err := client.Sys().TuneMount(backend, tune)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	path := fmt.Sprintf("%s/config", backend)
	data := map[string]interface{}{}

	configFields := []string{
		"anonymous_group_search",
		"binddn",
		"case_sensitive_names",
		"certificate",
		"deny_null_bind",
		"discoverdn",
		"groupattr",
		"groupdn",
		"groupfilter",
		"insecure_tls",
		"password_policy",
		"request_timeout",
		"schema",
		"starttls",
		"tls_max_version",
		"tls_min_version",
		"upndomain",
		"url",
		"use_token_groups",
		"userattr",
		"userdn",
		"userfilter",
		"username_as_alias",
	}
	for _, k := range configFields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}
	data["schema"] = d.Get("schema") // Schema always reverts to openldap if we don't specify it when modifying for some reason

	if len(data) > 0 {
		log.Printf("[DEBUG] Updating %q", path)

		if _, err := client.Logical().Write(path, data); err != nil {
			return diag.Errorf("error writing config to mount %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated %q", path)
	} else {
		log.Printf("[DEBUG] Nothing to update for %q", path)
	}

	return ldapSecretBackendRead(ctx, d, meta)
}

func deleteLdapSecretBackend(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Unmounting LDAP backend %q", path)

	err := client.Sys().Unmount(path)
	if err != nil && util.Is404(err) {
		log.Printf("[WARN] %q not found, removing from state", path)
		d.SetId("")
		return diag.FromErr(err)
	} else if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Unmounted LDAP backend %q", path)

	return nil
}
