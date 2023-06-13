// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	databaseSecretBackendRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/roles/.+$")
	databaseSecretBackendRoleNameFromPathRegex    = regexp.MustCompile("^.+/roles/(.+$)")
)

func databaseSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: databaseSecretBackendRoleWrite,
		Read:   provider.ReadWrapper(databaseSecretBackendRoleRead),
		Update: databaseSecretBackendRoleWrite,
		Delete: databaseSecretBackendRoleDelete,
		Exists: databaseSecretBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the role.",
			},
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the Database Secret Backend the role belongs to.",
			},
			consts.FieldDBName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Database connection to use for this role.",
			},
			consts.FieldDefaultTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Default TTL for leases associated with this role, in seconds.",
			},
			consts.FieldMaxTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum TTL for leases associated with this role, in seconds.",
			},
			consts.FieldCreationStatements: {
				Type:        schema.TypeList,
				Required:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Database statements to execute to create and configure a user.",
			},
			consts.FieldRevocationStatements: {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Database statements to execute to revoke a user.",
			},
			consts.FieldRollbackStatements: {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Database statements to execute to rollback a create operation in the event of an error.",
			},
			consts.FieldRenewStatements: {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Database statements to execute to renew a user.",
			},
			consts.FieldCredentialConfig: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Specifies the configuration for the given credential_type.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldCACert: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The PEM-encoded CA certificate.",
			},
			consts.FieldCAPrivateKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The PEM-encoded private key for the given ca_cert.",
			},
			consts.FieldKeyType: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the desired key type. Options include: rsa, ed25519, ec.",
			},
			consts.FieldKeyBits: {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  2048,
				Description: "Number of bits to use for the generated keys. Options include: 2048 " +
					"(default), 3072, 4096; with key_type=ec, allowed values are: 224, 256 (default), " +
					"384, 521; ignored with key_type=ed25519.",
			},
			consts.FieldSignatureBits: {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  256,
				Description: "The number of bits to use in the signature algorithm. Options include: 256 " +
					"(default), 384, 512.",
			},
			consts.FieldCommonNameTemplate: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "A username template to be used for the client certificate common name.",
			},
		},
	}
}

func databaseSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get(consts.FieldBackend).(string)
	name := d.Get(consts.FieldName).(string)

	path := databaseSecretBackendRolePath(backend, name)

	data := map[string]interface{}{
		"db_name":             d.Get(consts.FieldDBName),
		"creation_statements": d.Get(consts.FieldCreationStatements),
	}
	fields := []string{
		consts.FieldDefaultTTL,
		consts.FieldMaxTTL,
		consts.FieldRevocationStatements,
		consts.FieldRollbackStatements,
		consts.FieldRenewStatements,
		consts.FieldCredentialConfig, // ??
		consts.FieldCACert,
		consts.FieldPrivateKey,
		consts.FieldKeyType,
		consts.FieldKeyBits,
		consts.FieldSignatureBits,
		consts.FieldCommonNameTemplate,
	}
	for _, k := range fields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	//if v, ok := d.GetOkExists("default_ttl"); ok {
	//	data["default_ttl"] = v
	//}
	//if v, ok := d.GetOkExists("max_ttl"); ok {
	//	data["max_ttl"] = v
	//}
	//if v, ok := d.GetOkExists("revocation_statements"); ok && v != "" {
	//	data["revocation_statements"] = v
	//}
	//if v, ok := d.GetOkExists("rollback_statements"); ok && v != "" {
	//	data["rollback_statements"] = v
	//}
	//if v, ok := d.GetOkExists("renew_statements"); ok && v != "" {
	//	data["renew_statements"] = v
	//}

	log.Printf("[DEBUG] Creating role %q on database backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating role %q for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created role %q on AWS backend %q", name, backend)

	d.SetId(path)
	return databaseSecretBackendRoleRead(d, meta)
}

func databaseSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	name, err := databaseSecretBackendRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing database role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid role ID %q: %s", path, err)
	}

	backend, err := databaseSecretBackendRoleBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing database role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading role from %q", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read role from %q", path)
	if secret == nil {
		log.Printf("[WARN] Role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	d.Set("backend", backend)
	d.Set("name", name)
	d.Set("db_name", secret.Data["db_name"])
	var creation []string
	if creationStr, ok := secret.Data["creation_statements"].(string); ok {
		creation = append(creation, creationStr)
	} else if creations, ok := secret.Data["creation_statements"].([]interface{}); ok {
		for _, cr := range creations {
			creation = append(creation, cr.(string))
		}
	}
	d.Set("creation_statements", creation)
	var revocation []string
	if revocationStr, ok := secret.Data["revocation_statements"].(string); ok {
		revocation = append(revocation, revocationStr)
	} else if revocations, ok := secret.Data["revocation_statements"].([]interface{}); ok {
		for _, rev := range revocations {
			revocation = append(revocation, rev.(string))
		}
	}
	d.Set("revocation_statements", revocation)
	var rollback []string
	if rollbackStr, ok := secret.Data["rollback_statements"].(string); ok {
		rollback = append(rollback, rollbackStr)
	} else if rollbacks, ok := secret.Data["rollback_statements"].([]interface{}); ok {
		for _, rb := range rollbacks {
			rollback = append(rollback, rb.(string))
		}
	}
	d.Set("rollback_statements", rollback)
	var renew []string
	if renewStr, ok := secret.Data["renew_statements"].(string); ok {
		renew = append(renew, renewStr)
	} else if renews, ok := secret.Data["renew_statements"].([]interface{}); ok {
		for _, ren := range renews {
			renew = append(renew, ren.(string))
		}
	}
	d.Set("renew_statements", renew)

	if v, ok := secret.Data["default_ttl"]; ok {
		n, err := v.(json.Number).Int64()
		if err != nil {
			return fmt.Errorf("unexpected value %q for default_ttl of %q", v, path)
		}
		d.Set("default_ttl", n)
	}
	if v, ok := secret.Data["max_ttl"]; ok {
		n, err := v.(json.Number).Int64()
		if err != nil {
			return fmt.Errorf("unexpected value %q for max_ttl of %q", v, path)
		}
		d.Set("max_ttl", n)
	}

	credentialConfig := make(map[string]string)
	if configStr, ok := secret.Data["credential_config"].(string); ok {
		parts := strings.Split(configStr, "=")
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.Trim(parts[1], `'"`) // Removing single or double quotes when storing
			credentialConfig[key] = value
		}
	}
	fields := []string{
		consts.FieldCACert,
		consts.FieldCAPrivateKey,
		consts.FieldKeyType,
		consts.FieldCommonNameTemplate,
	}
	for _, k := range fields {
		if err := d.Set(k, secret.Data[k]); err != nil {
			return fmt.Errorf("error setting state key %q on database secret backend role, err=%s", k, err)
		}
	}
	if v, ok := secret.Data["key_bits"]; ok {
		n, err := v.(json.Number).Int64()
		if err != nil {
			return fmt.Errorf("unexpected value %q for key_bits of %q", v, path)
		}
		d.Set("key_bits", n)
	}
	if v, ok := secret.Data["signature_bits"]; ok {
		n, err := v.(json.Number).Int64()
		if err != nil {
			return fmt.Errorf("unexpected value %q for signature_bits of %q", v, path)
		}
		d.Set("signature_bits", n)
	}

	return nil
}

func databaseSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Deleting role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted role %q", path)
	return nil
}

func databaseSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return secret != nil, nil
}

func databaseSecretBackendRolePath(backend, name string) string {
	return strings.Trim(backend, "/") + "/roles/" + strings.Trim(name, "/")
}

func databaseSecretBackendRoleNameFromPath(path string) (string, error) {
	if !databaseSecretBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := databaseSecretBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func databaseSecretBackendRoleBackendFromPath(path string) (string, error) {
	if !databaseSecretBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := databaseSecretBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
