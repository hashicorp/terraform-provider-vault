package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	databaseSecretBackendStaticRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/static-roles/.+$")
	databaseSecretBackendStaticRoleNameFromPathRegex    = regexp.MustCompile("^.+/static-roles/(.+$)")
)

func databaseSecretBackendStaticRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: databaseSecretBackendStaticRoleWrite,
		Read:   databaseSecretBackendStaticRoleRead,
		Update: databaseSecretBackendStaticRoleWrite,
		Delete: databaseSecretBackendStaticRoleDelete,
		Exists: databaseSecretBackendStaticRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the static role.",
			},
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the Database Secret Backend the role belongs to.",
			},
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The database username that this role corresponds to.",
			},
			"rotation_period": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "The amount of time Vault should wait before rotating the password, in seconds.",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(int)
					if value < 5 {
						errs = append(errs, fmt.Errorf("The minimum value of rotation_period is 5 seconds."))
					}
					return
				},
			},
			"db_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Database connection to use for this role.",
			},
			"rotation_statements": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Database statements to execute to rotate the password for the configured database user.",
			},
		},
	}
}

func databaseSecretBackendStaticRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := databaseSecretBackendStaticRolePath(backend, name)

	data := map[string]interface{}{
		"username":            d.Get("username"),
		"rotation_period":     d.Get("rotation_period"),
		"db_name":             d.Get("db_name"),
		"rotation_statements": []string{},
	}

	if v, ok := d.GetOkExists("rotation_statements"); ok && v != "" {
		data["rotation_statements"] = v
	}

	log.Printf("[DEBUG] Creating static role %q on database backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating static role %q for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created static role %q on AWS backend %q", name, backend)

	d.SetId(path)
	return databaseSecretBackendStaticRoleRead(d, meta)
}

func databaseSecretBackendStaticRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	name, err := databaseSecretBackendStaticRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing database static role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid static role ID %q: %s", path, err)
	}

	backend, err := databaseSecretBackendStaticRoleBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing database static role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid static role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading static role from %q", path)
	role, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading static role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read static role from %q", path)
	if role == nil {
		log.Printf("[WARN] Static role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set("backend", backend)
	d.Set("name", name)
	d.Set("username", role.Data["username"])
	d.Set("db_name", role.Data["db_name"])

	if v, ok := role.Data["rotation_period"]; ok {
		n, err := v.(json.Number).Int64()
		if err != nil {
			return fmt.Errorf("unexpected value %q for rotation_period of %q", v, path)
		}
		d.Set("rotation_period", n)
	}

	var rotation []string
	if rotationStr, ok := role.Data["rotation_statements"].(string); ok {
		rotation = append(rotation, rotationStr)
	} else if rotations, ok := role.Data["rotation_statements"].([]interface{}); ok {
		for _, cr := range rotations {
			rotation = append(rotation, cr.(string))
		}
	}
	err = d.Set("rotation_statements", rotation)
	if err != nil {
		return fmt.Errorf("unexpected value %q for rotation_statements of %s: %s", rotation, path, err)
	}

	return nil
}

func databaseSecretBackendStaticRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Deleting static role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting static role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted static role %q", path)
	return nil
}

func databaseSecretBackendStaticRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)
	role, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return role != nil, nil
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
