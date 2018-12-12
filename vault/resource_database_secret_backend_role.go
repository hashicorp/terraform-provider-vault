package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	databaseSecretBackendRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/roles/.+$")
	databaseSecretBackendRoleNameFromPathRegex    = regexp.MustCompile("^.+/roles/(.+$)")
)

func databaseSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: databaseSecretBackendRoleWrite,
		Read:   databaseSecretBackendRoleRead,
		Update: databaseSecretBackendRoleWrite,
		Delete: databaseSecretBackendRoleDelete,
		Exists: databaseSecretBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the role.",
			},
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the Database Secret Backend the role belongs to.",
			},
			"db_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Database connection to use for this role.",
			},
			"default_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Default TTL for leases associated with this role, in seconds.",
			},
			"max_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum TTL for leases associated with this role, in seconds.",
			},
			"creation_statements": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Database statements to execute to create and configure a user.",
			},
			"revocation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Database statements to execute to revoke a user.",
			},
			"rollback_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Database statements to execute to rollback a create operation in the event of an error.",
			},
			"renew_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Database statements to execute to renew a user.",
			},
		},
	}
}

func databaseSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := databaseSecretBackendRolePath(backend, name)

	data := map[string]interface{}{
		"db_name":             d.Get("db_name").(string),
		"creation_statements": d.Get("creation_statements").(string),
	}

	if v, ok := d.GetOkExists("default_ttl"); ok {
		data["default_ttl"] = v.(int)
	}
	if v, ok := d.GetOkExists("max_ttl"); ok {
		data["max_ttl"] = v.(int)
	}
	if v, ok := d.GetOkExists("revocation_statements"); ok && v != "" {
		data["revocation_statements"] = v.(string)
	}
	if v, ok := d.GetOkExists("rollback_statements"); ok && v != "" {
		data["rollback_statements"] = v.(string)
	}
	if v, ok := d.GetOkExists("renew_statements"); ok && v != "" {
		data["renew_statements"] = v.(string)
	}

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
	client := meta.(*api.Client)

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
	d.Set("creation_statements", secret.Data["creation_statements"])
	d.Set("revocation_statements", secret.Data["revocation_statements"])
	d.Set("rollback_statements", secret.Data["rollback_statements"])
	d.Set("renew_statements", secret.Data["renew_statements"])

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
	return nil
}

func databaseSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

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
	client := meta.(*api.Client)

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
