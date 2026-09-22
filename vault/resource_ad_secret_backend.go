// Copyright IBM Corp. 2016, 2026
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
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func adSecretBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldBackend: {
			Type:        schema.TypeString,
			Default:     consts.MountTypeAD,
			Optional:    true,
			Description: `The mount path for a backend, for example, the path given in "$ vault auth enable -path=my-ad ad".`,
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		consts.FieldAnonymousGroupSearch: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `Use anonymous binds when performing LDAP group searches (if true the initial credentials will still be used for the initial connection test).`,
		},
		consts.FieldBindDN: {
			Type:        schema.TypeString,
			Required:    true,
			Description: `Distinguished name of object to bind when performing user and group search.`,
		},
		consts.FieldBindPass: {
			Type:        schema.TypeString,
			Required:    true,
			Sensitive:   true,
			Description: `LDAP password for searching for the user DN.`,
		},
		consts.FieldCaseSensitiveNames: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `If true, case sensitivity will be used when comparing usernames and groups for matching policies.`,
		},
		consts.FieldCertificate: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `CA certificate to use when verifying LDAP server certificate, must be x509 PEM encoded.`,
		},
		consts.FieldClientTLSCert: {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: `Client certificate to provide to the LDAP server, must be x509 PEM encoded.`,
		},
		consts.FieldClientTLSKey: {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: `Client certificate key to provide to the LDAP server, must be x509 PEM encoded.`,
		},
		consts.FieldDefaultLeaseTTLSeconds: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Default lease duration for secrets in seconds",
		},
		consts.FieldDenyNullBind: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `Denies an unauthenticated LDAP bind request if the user's password is empty; defaults to true`,
		},
		consts.FieldDescription: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Human-friendly description of the mount for the backend.",
		},
		consts.FieldDiscoverDN: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `Use anonymous bind to discover the bind DN of a user.`,
		},
		consts.FieldGroupAttr: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `LDAP attribute to follow on objects returned by <groupfilter> in order to enumerate user group membership. Examples: "cn" or "memberOf", etc. Default: cn`,
		},
		consts.FieldGroupDN: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `LDAP search base to use for group membership search (eg: ou=Groups,dc=example,dc=org)`,
		},
		consts.FieldGroupFilter: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Go template for querying group membership of user. The template can access the following context variables: UserDN, Username Example: (&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}})) Default: (|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))`,
		},
		consts.FieldInsecureTLS: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `Skip LDAP server SSL Certificate verification - insecure and not recommended for production use.`,
		},
		consts.FieldLastRotationTolerance: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `The number of seconds after a Vault rotation where, if Active Directory shows a later rotation, it should be considered out-of-band.`,
		},
		consts.FieldLocal: {
			Type:        schema.TypeBool,
			Required:    false,
			Optional:    true,
			Description: "Mark the secrets engine as local-only. Local engines are not replicated or removed by replication.Tolerance duration to use when checking the last rotation time.",
		},
		consts.FieldMaxLeaseTTLSeconds: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
		consts.FieldMaxTTL: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `In seconds, the maximum password time-to-live.`,
		},
		consts.FieldPasswordPolicy: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Name of the password policy to use to generate passwords.`,
		},
		consts.FieldRequestTimeout: {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: `Timeout, in seconds, for the connection when making requests against the server before returning back an error.`,
		},
		consts.FieldStartTLS: {
			Type:        schema.TypeBool,
			Optional:    true,
			Computed:    true,
			Description: `Issue a StartTLS command after establishing unencrypted connection.`,
		},
		consts.FieldTLSMaxVersion: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: `Maximum TLS version to use. Accepted values are 'tls10', 'tls11', 'tls12' or 'tls13'. Defaults to 'tls12'`,
		},
		consts.FieldTLSMinVersion: {
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
		consts.FieldUPNDomain: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: `Enables userPrincipalDomain login with [username]@UPNDomain.`,
		},
		consts.FieldURL: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `LDAP URL to connect to (default: ldap://127.0.0.1). Multiple URLs can be specified by concatenating them with commas; they will be tried in-order.`,
		},
		consts.FieldUsePre111GroupCNBehavior: {
			Type:        schema.TypeBool,
			Optional:    true,
			Computed:    true,
			Description: `In Vault 1.1.1 a fix for handling group CN values of different cases unfortunately introduced a regression that could cause previously defined groups to not be found due to a change in the resulting name. If set true, the pre-1.1.1 behavior for matching group CNs will be used. This is only needed in some upgrade scenarios for backwards compatibility. It is enabled by default if the config is upgraded but disabled by default on new configurations.`,
		},
		consts.FieldUseTokenGroups: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `If true, use the Active Directory tokenGroups constructed attribute of the user to find the group memberships. This will find all security groups including nested ones.`,
		},
		consts.FieldUserAttr: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Attribute used for users (default: cn)`,
		},
		consts.FieldUserDN: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `LDAP domain to use for users (eg: ou=People,dc=example,dc=org)`,
		},
	}
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		DeprecationMessage: `This resource is replaced by "vault_ldap_secret_backend" and will be removed in the next major release.`,
		Create:             createConfigResource,
		Update:             updateConfigResource,
		Read:               provider.ReadWrapper(readConfigResource),
		Delete:             deleteConfigResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldBackend),
		Schema:        fields,
	}, false)
}

func createConfigResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get(consts.FieldBackend).(string)
	description := d.Get(consts.FieldDescription).(string)
	defaultTTL := d.Get(consts.FieldDefaultLeaseTTLSeconds).(int)
	local := d.Get(consts.FieldLocal).(bool)
	maxTTL := d.Get(consts.FieldMaxLeaseTTLSeconds).(int)

	log.Printf("[DEBUG] Mounting AD backend at %q", backend)
	err := client.Sys().Mount(backend, &api.MountInput{
		Type:        consts.MountTypeAD,
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
	if v, ok := d.GetOkExists(consts.FieldAnonymousGroupSearch); ok {
		data[consts.FieldAnonymousGroupSearch] = v
	}
	if v, ok := d.GetOkExists(consts.FieldBindDN); ok {
		data[consts.FieldBindDN] = v
	}
	if v, ok := d.GetOkExists(consts.FieldBindPass); ok {
		data[consts.FieldBindPass] = v
	}
	if v, ok := d.GetOkExists(consts.FieldCaseSensitiveNames); ok {
		data[consts.FieldCaseSensitiveNames] = v
	}
	if v, ok := d.GetOkExists(consts.FieldCertificate); ok {
		data[consts.FieldCertificate] = v
	}
	if v, ok := d.GetOkExists(consts.FieldClientTLSCert); ok {
		data[consts.FieldClientTLSCert] = v
	}
	if v, ok := d.GetOkExists(consts.FieldClientTLSKey); ok {
		data[consts.FieldClientTLSKey] = v
	}
	if v, ok := d.GetOkExists(consts.FieldDenyNullBind); ok {
		data[consts.FieldDenyNullBind] = v
	}
	if v, ok := d.GetOkExists(consts.FieldDiscoverDN); ok {
		data[consts.FieldDiscoverDN] = v
	}
	if v, ok := d.GetOkExists(consts.FieldGroupAttr); ok {
		data[consts.FieldGroupAttr] = v
	}
	if v, ok := d.GetOkExists(consts.FieldGroupDN); ok {
		data[consts.FieldGroupDN] = v
	}
	if v, ok := d.GetOkExists(consts.FieldGroupFilter); ok {
		data[consts.FieldGroupFilter] = v
	}
	if v, ok := d.GetOkExists(consts.FieldInsecureTLS); ok {
		data[consts.FieldInsecureTLS] = v
	}
	if v, ok := d.GetOkExists(consts.FieldLastRotationTolerance); ok {
		data[consts.FieldLastRotationTolerance] = v
	}
	if v, ok := d.GetOkExists(consts.FieldMaxTTL); ok {
		data[consts.FieldMaxTTL] = v
	}
	if v, ok := d.GetOkExists(consts.FieldPasswordPolicy); ok {
		data[consts.FieldPasswordPolicy] = v
	}
	if v, ok := d.GetOkExists(consts.FieldRequestTimeout); ok {
		data[consts.FieldRequestTimeout] = v
	}
	if v, ok := d.GetOkExists(consts.FieldStartTLS); ok {
		data[consts.FieldStartTLS] = v
	}
	if v, ok := d.GetOkExists(consts.FieldTLSMaxVersion); ok {
		data[consts.FieldTLSMaxVersion] = v
	}
	if v, ok := d.GetOkExists(consts.FieldTLSMinVersion); ok {
		data[consts.FieldTLSMinVersion] = v
	}
	if v, ok := d.GetOkExists(consts.FieldTTL); ok {
		data[consts.FieldTTL] = v
	}
	if v, ok := d.GetOkExists(consts.FieldUPNDomain); ok {
		data[consts.FieldUPNDomain] = v
	}
	if v, ok := d.GetOkExists(consts.FieldURL); ok {
		data[consts.FieldURL] = v
	}
	if v, ok := d.GetOkExists(consts.FieldUsePre111GroupCNBehavior); ok {
		data[consts.FieldUsePre111GroupCNBehavior] = v
	}
	if v, ok := d.GetOkExists(consts.FieldUseTokenGroups); ok {
		data[consts.FieldUseTokenGroups] = v
	}
	if v, ok := d.GetOkExists(consts.FieldUserAttr); ok {
		data[consts.FieldUserAttr] = v
	}
	if v, ok := d.GetOkExists(consts.FieldUserDN); ok {
		data[consts.FieldUserDN] = v
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
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Reading %q", path)

	ctx := context.Background()
	mount, err := mountutil.GetMount(ctx, client, path)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found, removing from state.", path)
			d.SetId("")
			return nil
		}
		return err
	}

	d.Set(consts.FieldBackend, d.Id())

	d.Set(consts.FieldDefaultLeaseTTLSeconds, mount.Config.DefaultLeaseTTL)
	d.Set(consts.FieldMaxLeaseTTLSeconds, mount.Config.MaxLeaseTTL)

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

	if val, ok := resp.Data[consts.FieldAnonymousGroupSearch]; ok {
		if err := d.Set(consts.FieldAnonymousGroupSearch, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldAnonymousGroupSearch, err)
		}
	}
	if val, ok := resp.Data[consts.FieldBindDN]; ok {
		if err := d.Set(consts.FieldBindDN, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldBindDN, err)
		}
	}
	if val, ok := resp.Data[consts.FieldCaseSensitiveNames]; ok {
		if err := d.Set(consts.FieldCaseSensitiveNames, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldCaseSensitiveNames, err)
		}
	}
	if val, ok := resp.Data[consts.FieldClientTLSCert]; ok {
		if err := d.Set(consts.FieldClientTLSCert, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldClientTLSCert, err)
		}
	}
	if val, ok := resp.Data[consts.FieldClientTLSKey]; ok {
		if err := d.Set(consts.FieldClientTLSKey, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldClientTLSKey, err)
		}
	}
	if val, ok := resp.Data[consts.FieldDenyNullBind]; ok {
		if err := d.Set(consts.FieldDenyNullBind, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldDenyNullBind, err)
		}
	}
	if val, ok := resp.Data[consts.FieldDiscoverDN]; ok {
		if err := d.Set(consts.FieldDiscoverDN, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldDiscoverDN, err)
		}
	}
	if val, ok := resp.Data[consts.FieldGroupAttr]; ok {
		if err := d.Set(consts.FieldGroupAttr, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldGroupAttr, err)
		}
	}
	if val, ok := resp.Data[consts.FieldGroupDN]; ok {
		if err := d.Set(consts.FieldGroupDN, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldGroupDN, err)
		}
	}
	if val, ok := resp.Data[consts.FieldGroupFilter]; ok {
		if err := d.Set(consts.FieldGroupFilter, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldGroupFilter, err)
		}
	}
	if val, ok := resp.Data[consts.FieldInsecureTLS]; ok {
		if err := d.Set(consts.FieldInsecureTLS, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldInsecureTLS, err)
		}
	}
	if val, ok := resp.Data[consts.FieldLastRotationTolerance]; ok {
		if err := d.Set(consts.FieldLastRotationTolerance, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldLastRotationTolerance, err)
		}
	}
	if val, ok := resp.Data[consts.FieldMaxTTL]; ok {
		if err := d.Set(consts.FieldMaxTTL, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldMaxTTL, err)
		}
	}
	if val, ok := resp.Data[consts.FieldPasswordPolicy]; ok {
		if err := d.Set(consts.FieldPasswordPolicy, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldPasswordPolicy, err)
		}
	}
	if val, ok := resp.Data[consts.FieldRequestTimeout]; ok {
		if err := d.Set(consts.FieldRequestTimeout, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldRequestTimeout, err)
		}
	}
	if val, ok := resp.Data[consts.FieldStartTLS]; ok {
		if err := d.Set(consts.FieldStartTLS, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldStartTLS, err)
		}
	}
	if val, ok := resp.Data[consts.FieldTLSMaxVersion]; ok {
		if err := d.Set(consts.FieldTLSMaxVersion, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldTLSMaxVersion, err)
		}
	}
	if val, ok := resp.Data[consts.FieldTLSMinVersion]; ok {
		if err := d.Set(consts.FieldTLSMinVersion, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldTLSMinVersion, err)
		}
	}
	if val, ok := resp.Data[consts.FieldTTL]; ok {
		if err := d.Set(consts.FieldTTL, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldTTL, err)
		}
	}
	if val, ok := resp.Data[consts.FieldUPNDomain]; ok {
		if err := d.Set(consts.FieldUPNDomain, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldUPNDomain, err)
		}
	}
	if val, ok := resp.Data[consts.FieldURL]; ok {
		if err := d.Set(consts.FieldURL, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldURL, err)
		}
	}
	if val, ok := resp.Data[consts.FieldUsePre111GroupCNBehavior]; ok {
		if err := d.Set(consts.FieldUsePre111GroupCNBehavior, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldUsePre111GroupCNBehavior, err)
		}
	}
	if val, ok := resp.Data[consts.FieldUseTokenGroups]; ok {
		if err := d.Set(consts.FieldUseTokenGroups, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldUseTokenGroups, err)
		}
	}
	if val, ok := resp.Data[consts.FieldUserAttr]; ok {
		if err := d.Set(consts.FieldUserAttr, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldUserAttr, err)
		}
	}
	if val, ok := resp.Data[consts.FieldUserDN]; ok {
		if err := d.Set(consts.FieldUserDN, val); err != nil {
			return fmt.Errorf("error setting state key '%s': %s", consts.FieldUserDN, err)
		}
	}
	return nil
}

func updateConfigResource(d *schema.ResourceData, meta interface{}) error {
	backend := d.Id()

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend, e = util.Remount(d, client, consts.FieldBackend, false)
	if e != nil {
		return e
	}

	defaultTTL := d.Get(consts.FieldDefaultLeaseTTLSeconds).(int)
	maxTTL := d.Get(consts.FieldMaxLeaseTTLSeconds).(int)
	tune := api.MountConfigInput{}
	data := map[string]interface{}{}

	if defaultTTL != 0 {
		tune.DefaultLeaseTTL = fmt.Sprintf("%ds", defaultTTL)
		data[consts.FieldDefaultLeaseTTLSeconds] = defaultTTL
	}

	if maxTTL != 0 {
		tune.MaxLeaseTTL = fmt.Sprintf("%ds", maxTTL)
		data[consts.FieldMaxLeaseTTLSeconds] = maxTTL
	}

	if tune.DefaultLeaseTTL != "0" || tune.MaxLeaseTTL != "0" {
		err := client.Sys().TuneMount(backend, tune)
		if err != nil {
			return fmt.Errorf("error mounting to %q: %s", backend, err)
		}
	}

	vaultPath := fmt.Sprintf("%s/config", backend)
	log.Printf("[DEBUG] Updating %q", vaultPath)

	if raw, ok := d.GetOk(consts.FieldAnonymousGroupSearch); ok {
		data[consts.FieldAnonymousGroupSearch] = raw
	}
	if raw, ok := d.GetOk(consts.FieldBindDN); ok {
		data[consts.FieldBindDN] = raw
	}
	if raw, ok := d.GetOk(consts.FieldBindPass); ok {
		data[consts.FieldBindPass] = raw
	}
	if raw, ok := d.GetOk(consts.FieldCaseSensitiveNames); ok {
		data[consts.FieldCaseSensitiveNames] = raw
	}
	if raw, ok := d.GetOk(consts.FieldCertificate); ok {
		data[consts.FieldCertificate] = raw
	}
	if raw, ok := d.GetOk(consts.FieldClientTLSCert); ok {
		data[consts.FieldClientTLSCert] = raw
	}
	if raw, ok := d.GetOk(consts.FieldClientTLSKey); ok {
		data[consts.FieldClientTLSKey] = raw
	}
	if raw, ok := d.GetOk(consts.FieldDenyNullBind); ok {
		data[consts.FieldDenyNullBind] = raw
	}
	if raw, ok := d.GetOk(consts.FieldDiscoverDN); ok {
		data[consts.FieldDiscoverDN] = raw
	}
	if raw, ok := d.GetOk(consts.FieldGroupAttr); ok {
		data[consts.FieldGroupAttr] = raw
	}
	if raw, ok := d.GetOk(consts.FieldGroupDN); ok {
		data[consts.FieldGroupDN] = raw
	}
	if raw, ok := d.GetOk(consts.FieldGroupFilter); ok {
		data[consts.FieldGroupFilter] = raw
	}
	if raw, ok := d.GetOk(consts.FieldLastRotationTolerance); ok {
		data[consts.FieldLastRotationTolerance] = raw
	}
	if raw, ok := d.GetOk(consts.FieldMaxTTL); ok {
		data[consts.FieldMaxTTL] = raw
	}
	if raw, ok := d.GetOk(consts.FieldPasswordPolicy); ok {
		data[consts.FieldPasswordPolicy] = raw
	}
	if raw, ok := d.GetOk(consts.FieldRequestTimeout); ok {
		data[consts.FieldRequestTimeout] = raw
	}
	if raw, ok := d.GetOk(consts.FieldStartTLS); ok {
		data[consts.FieldStartTLS] = raw
	}
	if raw, ok := d.GetOk(consts.FieldTLSMaxVersion); ok {
		data[consts.FieldTLSMaxVersion] = raw
	}
	if raw, ok := d.GetOk(consts.FieldTLSMinVersion); ok {
		data[consts.FieldTLSMinVersion] = raw
	}
	if raw, ok := d.GetOk(consts.FieldTTL); ok {
		data[consts.FieldTTL] = raw
	}
	if raw, ok := d.GetOk(consts.FieldUPNDomain); ok {
		data[consts.FieldUPNDomain] = raw
	}
	if raw, ok := d.GetOk(consts.FieldURL); ok {
		data[consts.FieldURL] = raw
	}
	if raw, ok := d.GetOk(consts.FieldUsePre111GroupCNBehavior); ok {
		data[consts.FieldUsePre111GroupCNBehavior] = raw
	}
	if raw, ok := d.GetOk(consts.FieldUseTokenGroups); ok {
		data[consts.FieldUseTokenGroups] = raw
	}
	if raw, ok := d.GetOk(consts.FieldUserAttr); ok {
		data[consts.FieldUserAttr] = raw
	}
	if raw, ok := d.GetOk(consts.FieldUserDN); ok {
		data[consts.FieldUserDN] = raw
	}
	data[consts.FieldInsecureTLS] = d.Get(consts.FieldInsecureTLS)
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return fmt.Errorf("error updating template auth backend role %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Updated %q", vaultPath)
	return readConfigResource(d, meta)
}

func deleteConfigResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

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
