package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-provider-vault/util"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func adSecretBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"backend": {
			Type:        schema.TypeString,
			Default:     "ad",
			ForceNew:    true,
			Optional:    true,
			Description: `The mount path for a backend, for example, the path given in "$ vault auth enable -path=my-ad ad".`,
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"anonymous_group_search": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `Use anonymous binds when performing LDAP group searches (if true the initial credentials will still be used for the initial connection test).`,
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
			Optional:    true,
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
		"default_lease_ttl_seconds": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Default lease duration for secrets in seconds",
		},
		"deny_null_bind": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `Denies an unauthenticated LDAP bind request if the user's password is empty; defaults to true`,
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Human-friendly description of the mount for the backend.",
		},
		"discoverdn": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `Use anonymous bind to discover the bind DN of a user.`,
		},
		"formatter": {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Deprecated:  `Formatter is deprecated and password_policy should be used with Vault >= 1.5.`,
			Description: `Text to insert the password into, ex. "customPrefix{{PASSWORD}}customSuffix".`,
		},
		"groupattr": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `LDAP attribute to follow on objects returned by <groupfilter> in order to enumerate user group membership. Examples: "cn" or "memberOf", etc. Default: cn`,
		},
		"groupdn": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `LDAP search base to use for group membership search (eg: ou=Groups,dc=example,dc=org)`,
		},
		"groupfilter": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Go template for querying group membership of user. The template can access the following context variables: UserDN, Username Example: (&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}})) Default: (|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))`,
		},
		"insecure_tls": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `Skip LDAP server SSL Certificate verification - insecure and not recommended for production use.`,
		},
		"last_rotation_tolerance": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `The number of seconds after a Vault rotation where, if Active Directory shows a later rotation, it should be considered out-of-band.`,
		},
		"length": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Deprecated:  `Length is deprecated and password_policy should be used with Vault >= 1.5.`,
			Description: `The desired length of passwords that Vault generates.`,
		},
		"local": {
			Type:        schema.TypeBool,
			Required:    false,
			Optional:    true,
			Description: "Mark the secrets engine as local-only. Local engines are not replicated or removed by replication.Tolerance duration to use when checking the last rotation time.",
		},
		"max_lease_ttl_seconds": {
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
		"request_timeout": {
			Type:        schema.TypeInt,
			Optional:    true,
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
		"ttl": {
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
		"use_pre111_group_cn_behavior": {
			Type:        schema.TypeBool,
			Optional:    true,
			Computed:    true,
			Description: `In Vault 1.1.1 a fix for handling group CN values of different cases unfortunately introduced a regression that could cause previously defined groups to not be found due to a change in the resulting name. If set true, the pre-1.1.1 behavior for matching group CNs will be used. This is only needed in some upgrade scenarios for backwards compatibility. It is enabled by default if the config is upgraded but disabled by default on new configurations.`,
		},
		"use_token_groups": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `If true, use the Active Directory tokenGroups constructed attribute of the user to find the group memberships. This will find all security groups including nested ones.`,
		},
		"userattr": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Attribute used for users (default: cn)`,
		},
		"userdn": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `LDAP domain to use for users (eg: ou=People,dc=example,dc=org)`,
		},
	}
	return &schema.Resource{
		Create: createConfigResource,
		Update: updateConfigResource,
		Read:   readConfigResource,
		Delete: deleteConfigResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func createConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	backend := d.Get("backend").(string)
	description := d.Get("description").(string)
	defaultTTL := d.Get("default_lease_ttl_seconds").(int)
	local := d.Get("local").(bool)
	maxTTL := d.Get("max_lease_ttl_seconds").(int)

	log.Printf("[DEBUG] Mounting AD backend at %q", backend)
	err := client.Sys().Mount(backend, &api.MountInput{
		Type:        "ad",
		Description: description,
		Local:       local,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
			MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
		},
	})
	if err != nil {
		return fmt.Errorf("error mounting to %q: %s", backend, err)
	}

	log.Printf("[DEBUG] Mounted AD backend at %q", backend)
	d.SetId(backend)

	data := map[string]interface{}{}
	if v, ok := d.GetOkExists("anonymous_group_search"); ok {
		data["anonymous_group_search"] = v
	}
	if v, ok := d.GetOkExists("binddn"); ok {
		data["binddn"] = v
	}
	if v, ok := d.GetOkExists("bindpass"); ok {
		data["bindpass"] = v
	}
	if v, ok := d.GetOkExists("case_sensitive_names"); ok {
		data["case_sensitive_names"] = v
	}
	if v, ok := d.GetOkExists("certificate"); ok {
		data["certificate"] = v
	}
	if v, ok := d.GetOkExists("client_tls_cert"); ok {
		data["client_tls_cert"] = v
	}
	if v, ok := d.GetOkExists("client_tls_key"); ok {
		data["client_tls_key"] = v
	}
	if v, ok := d.GetOkExists("deny_null_bind"); ok {
		data["deny_null_bind"] = v
	}
	if v, ok := d.GetOkExists("discoverdn"); ok {
		data["discoverdn"] = v
	}
	if v, ok := d.GetOkExists("formatter"); ok {
		data["formatter"] = v
	}
	if v, ok := d.GetOkExists("groupattr"); ok {
		data["groupattr"] = v
	}
	if v, ok := d.GetOkExists("groupdn"); ok {
		data["groupdn"] = v
	}
	if v, ok := d.GetOkExists("groupfilter"); ok {
		data["groupfilter"] = v
	}
	if v, ok := d.GetOkExists("insecure_tls"); ok {
		data["insecure_tls"] = v
	}
	if v, ok := d.GetOkExists("last_rotation_tolerance"); ok {
		data["last_rotation_tolerance"] = v
	}
	if v, ok := d.GetOkExists("length"); ok {
		data["length"] = v
	}
	if v, ok := d.GetOkExists("max_ttl"); ok {
		data["max_ttl"] = v
	}
	if v, ok := d.GetOkExists("password_policy"); ok {
		data["password_policy"] = v
	}
	if v, ok := d.GetOkExists("request_timeout"); ok {
		data["request_timeout"] = v
	}
	if v, ok := d.GetOkExists("starttls"); ok {
		data["starttls"] = v
	}
	if v, ok := d.GetOkExists("tls_max_version"); ok {
		data["tls_max_version"] = v
	}
	if v, ok := d.GetOkExists("tls_min_version"); ok {
		data["tls_min_version"] = v
	}
	if v, ok := d.GetOkExists("ttl"); ok {
		data["ttl"] = v
	}
	if v, ok := d.GetOkExists("upndomain"); ok {
		data["upndomain"] = v
	}
	if v, ok := d.GetOkExists("url"); ok {
		data["url"] = v
	}
	if v, ok := d.GetOkExists("use_pre111_group_cn_behavior"); ok {
		data["use_pre111_group_cn_behavior"] = v
	}
	if v, ok := d.GetOkExists("use_token_groups"); ok {
		data["use_token_groups"] = v
	}
	if v, ok := d.GetOkExists("userattr"); ok {
		data["userattr"] = v
	}
	if v, ok := d.GetOkExists("userdn"); ok {
		data["userdn"] = v
	}

	configPath := fmt.Sprintf("%s/config", backend)
	log.Printf("[DEBUG] Writing %q", configPath)
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("error writing %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Wrote %q", configPath)
	return readConfigResource(d, meta)
}

func readConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Reading %q", path)

	mountResp, err := client.Sys().MountConfig(path)
	if err != nil && util.Is404(err) {
		log.Printf("[WARN] %q not found, removing from state", path)
		d.SetId("")
		return nil
	} else if err != nil {
		return fmt.Errorf("error reading %q: %s", path, err)
	}

	d.Set("backend", d.Id())

	d.Set("default_lease_ttl_seconds", mountResp.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mountResp.MaxLeaseTTL)

	configPath := fmt.Sprintf("%s/config", d.Id())
	log.Printf("[DEBUG] Reading %q", configPath)

	resp, err := client.Logical().Read(configPath)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Read %q", configPath)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", configPath)
		d.SetId("")
		return nil
	}

	if val, ok := resp.Data["anonymous_group_search"]; ok {
		if err := d.Set("anonymous_group_search", val); err != nil {
			return fmt.Errorf("error setting state key 'anonymous_group_search': %s", err)
		}
	}
	if val, ok := resp.Data["binddn"]; ok {
		if err := d.Set("binddn", val); err != nil {
			return fmt.Errorf("error setting state key 'binddn': %s", err)
		}
	}
	if val, ok := resp.Data["case_sensitive_names"]; ok {
		if err := d.Set("case_sensitive_names", val); err != nil {
			return fmt.Errorf("error setting state key 'case_sensitive_names': %s", err)
		}
	}
	if val, ok := resp.Data["client_tls_cert"]; ok {
		if err := d.Set("client_tls_cert", val); err != nil {
			return fmt.Errorf("error setting state key 'client_tls_cert': %s", err)
		}
	}
	if val, ok := resp.Data["client_tls_key"]; ok {
		if err := d.Set("client_tls_key", val); err != nil {
			return fmt.Errorf("error setting state key 'client_tls_key': %s", err)
		}
	}
	if val, ok := resp.Data["deny_null_bind"]; ok {
		if err := d.Set("deny_null_bind", val); err != nil {
			return fmt.Errorf("error setting state key 'deny_null_bind': %s", err)
		}
	}
	if val, ok := resp.Data["discoverdn"]; ok {
		if err := d.Set("discoverdn", val); err != nil {
			return fmt.Errorf("error setting state key 'discoverdn': %s", err)
		}
	}
	if val, ok := resp.Data["formatter"]; ok {
		if err := d.Set("formatter", val); err != nil {
			return fmt.Errorf("error setting state key 'formatter': %s", err)
		}
	}
	if val, ok := resp.Data["groupattr"]; ok {
		if err := d.Set("groupattr", val); err != nil {
			return fmt.Errorf("error setting state key 'groupattr': %s", err)
		}
	}
	if val, ok := resp.Data["groupdn"]; ok {
		if err := d.Set("groupdn", val); err != nil {
			return fmt.Errorf("error setting state key 'groupdn': %s", err)
		}
	}
	if val, ok := resp.Data["groupfilter"]; ok {
		if err := d.Set("groupfilter", val); err != nil {
			return fmt.Errorf("error setting state key 'groupfilter': %s", err)
		}
	}
	if val, ok := resp.Data["insecure_tls"]; ok {
		if err := d.Set("insecure_tls", val); err != nil {
			return fmt.Errorf("error setting state key 'insecure_tls': %s", err)
		}
	}
	if val, ok := resp.Data["last_rotation_tolerance"]; ok {
		if err := d.Set("last_rotation_tolerance", val); err != nil {
			return fmt.Errorf("error setting state key 'last_rotation_tolerance': %s", err)
		}
	}
	if val, ok := resp.Data["length"]; ok {
		if err := d.Set("length", val); err != nil {
			return fmt.Errorf("error setting state key 'length': %s", err)
		}
	}
	if val, ok := resp.Data["max_ttl"]; ok {
		if err := d.Set("max_ttl", val); err != nil {
			return fmt.Errorf("error setting state key 'max_ttl': %s", err)
		}
	}
	if val, ok := resp.Data["password_policy"]; ok {
		if err := d.Set("password_policy", val); err != nil {
			return fmt.Errorf("error setting state key 'password_policy': %s", err)
		}
	}
	if val, ok := resp.Data["request_timeout"]; ok {
		if err := d.Set("request_timeout", val); err != nil {
			return fmt.Errorf("error setting state key 'request_timeout': %s", err)
		}
	}
	if val, ok := resp.Data["starttls"]; ok {
		if err := d.Set("starttls", val); err != nil {
			return fmt.Errorf("error setting state key 'starttls': %s", err)
		}
	}
	if val, ok := resp.Data["tls_max_version"]; ok {
		if err := d.Set("tls_max_version", val); err != nil {
			return fmt.Errorf("error setting state key 'tls_max_version': %s", err)
		}
	}
	if val, ok := resp.Data["tls_min_version"]; ok {
		if err := d.Set("tls_min_version", val); err != nil {
			return fmt.Errorf("error setting state key 'tls_min_version': %s", err)
		}
	}
	if val, ok := resp.Data["ttl"]; ok {
		if err := d.Set("ttl", val); err != nil {
			return fmt.Errorf("error setting state key 'ttl': %s", err)
		}
	}
	if val, ok := resp.Data["upndomain"]; ok {
		if err := d.Set("upndomain", val); err != nil {
			return fmt.Errorf("error setting state key 'upndomain': %s", err)
		}
	}
	if val, ok := resp.Data["url"]; ok {
		if err := d.Set("url", val); err != nil {
			return fmt.Errorf("error setting state key 'url': %s", err)
		}
	}
	if val, ok := resp.Data["use_pre111_group_cn_behavior"]; ok {
		if err := d.Set("use_pre111_group_cn_behavior", val); err != nil {
			return fmt.Errorf("error setting state key 'use_pre111_group_cn_behavior': %s", err)
		}
	}
	if val, ok := resp.Data["use_token_groups"]; ok {
		if err := d.Set("use_token_groups", val); err != nil {
			return fmt.Errorf("error setting state key 'use_token_groups': %s", err)
		}
	}
	if val, ok := resp.Data["userattr"]; ok {
		if err := d.Set("userattr", val); err != nil {
			return fmt.Errorf("error setting state key 'userattr': %s", err)
		}
	}
	if val, ok := resp.Data["userdn"]; ok {
		if err := d.Set("userdn", val); err != nil {
			return fmt.Errorf("error setting state key 'userdn': %s", err)
		}
	}
	return nil
}

func updateConfigResource(d *schema.ResourceData, meta interface{}) error {
	backend := d.Id()

	client := meta.(*api.Client)
	defaultTTL := d.Get("default_lease_ttl_seconds").(int)
	maxTTL := d.Get("max_lease_ttl_seconds").(int)
	tune := api.MountConfigInput{}
	data := map[string]interface{}{}

	if defaultTTL != 0 {
		tune.DefaultLeaseTTL = fmt.Sprintf("%ds", defaultTTL)
		data["default_lease_ttl_seconds"] = defaultTTL
	}

	if maxTTL != 0 {
		tune.MaxLeaseTTL = fmt.Sprintf("%ds", maxTTL)
		data["max_lease_ttl_seconds"] = maxTTL
	}

	if tune.DefaultLeaseTTL != "0" || tune.MaxLeaseTTL != "0" {
		err := client.Sys().TuneMount(backend, tune)
		if err != nil {
			return fmt.Errorf("error mounting to %q: %s", backend, err)
		}
	}

	vaultPath := fmt.Sprintf("%s/config", backend)
	log.Printf("[DEBUG] Updating %q", vaultPath)

	if raw, ok := d.GetOk("anonymous_group_search"); ok {
		data["anonymous_group_search"] = raw
	}
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
	if raw, ok := d.GetOk("deny_null_bind"); ok {
		data["deny_null_bind"] = raw
	}
	if raw, ok := d.GetOk("discoverdn"); ok {
		data["discoverdn"] = raw
	}
	if raw, ok := d.GetOk("formatter"); ok {
		data["formatter"] = raw
	}
	if raw, ok := d.GetOk("groupattr"); ok {
		data["groupattr"] = raw
	}
	if raw, ok := d.GetOk("groupdn"); ok {
		data["groupdn"] = raw
	}
	if raw, ok := d.GetOk("groupfilter"); ok {
		data["groupfilter"] = raw
	}
	if raw, ok := d.GetOk("insecure_tls"); ok {
		data["insecure_tls"] = raw
	}
	if raw, ok := d.GetOk("last_rotation_tolerance"); ok {
		data["last_rotation_tolerance"] = raw
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
	if raw, ok := d.GetOk("use_token_groups"); ok {
		data["use_token_groups"] = raw
	}
	if raw, ok := d.GetOk("userattr"); ok {
		data["userattr"] = raw
	}
	if raw, ok := d.GetOk("userdn"); ok {
		data["userdn"] = raw
	}
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return fmt.Errorf("error updating template auth backend role %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Updated %q", vaultPath)
	return readConfigResource(d, meta)
}

func deleteConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Unmounting AD backend %q", vaultPath)

	err := client.Sys().Unmount(vaultPath)
	if err != nil && util.Is404(err) {
		log.Printf("[WARN] %q not found, removing from state", vaultPath)
		d.SetId("")
		return fmt.Errorf("error unmounting AD backend from %q: %s", vaultPath, err)
	} else if err != nil {
		return fmt.Errorf("error unmounting AD backend from %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Unmounted AD backend %q", vaultPath)
	return nil
}
