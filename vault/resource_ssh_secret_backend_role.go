package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	sshSecretBackendRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/roles/.+$")
	sshSecretBackendRoleNameFromPathRegex    = regexp.MustCompile("^.+/roles/(.+$)")
)

func sshSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: sshSecretBackendRoleWrite,
		Read:   sshSecretBackendRoleRead,
		Update: sshSecretBackendRoleWrite,
		Delete: sshSecretBackendRoleDelete,
		Exists: sshSecretBackendRoleExists,
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
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"allow_bare_domains": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"allow_host_certificates": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"allow_subdomains": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"allow_user_certificates": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"allow_user_key_ids": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"allowed_critical_options": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"allowed_domains": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cidr_list": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"allowed_extensions": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"default_extensions": {
				Type:     schema.TypeMap,
				Optional: true,
			},
			"default_critical_options": {
				Type:     schema.TypeMap,
				Optional: true,
			},
			"allowed_users": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"default_user": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"key_id_format": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"key_type": {
				Type:     schema.TypeString,
				Required: true,
			},
			"max_ttl": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"ttl": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func sshSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := sshRoleResourcePath(backend, name)

	data := map[string]interface{}{
		"key_type":                d.Get("key_type").(string),
		"allow_bare_domains":      d.Get("allow_bare_domains").(bool),
		"allow_host_certificates": d.Get("allow_host_certificates").(bool),
		"allow_subdomains":        d.Get("allow_subdomains").(bool),
		"allow_user_certificates": d.Get("allow_user_certificates").(bool),
		"allow_user_key_ids":      d.Get("allow_user_key_ids").(bool),
	}

	if v, ok := d.GetOk("allowed_critical_options"); ok {
		data["allowed_critical_options"] = v.(string)
	}

	if v, ok := d.GetOk("allowed_domains"); ok {
		data["allowed_domains"] = v.(string)
	}

	if v, ok := d.GetOk("cidr_list"); ok {
		data["cidr_list"] = v.(string)
	}

	if v, ok := d.GetOk("allowed_extensions"); ok {
		data["allowed_extensions"] = v.(string)
	}

	if v, ok := d.GetOk("default_extensions"); ok {
		data["default_extensions"] = v
	}

	if v, ok := d.GetOk("default_critical_options"); ok {
		data["default_critical_options"] = v
	}

	if v, ok := d.GetOk("allowed_users"); ok {
		data["allowed_users"] = v.(string)
	}

	if v, ok := d.GetOk("default_user"); ok {
		data["default_user"] = v.(string)
	}

	if v, ok := d.GetOk("key_id_format"); ok {
		data["key_id_format"] = v.(string)
	}

	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(string)
	}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(string)
	}

	log.Printf("[DEBUG] Writing role %q on SSH backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing role %q for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Wrote role %q on SSH backend %q", name, backend)

	d.SetId(path)
	return sshSecretBackendRoleRead(d, meta)
}

func sshSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	name, err := sshSecretBackendRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing ssh role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid role ID %q: %s", path, err)
	}

	backend, err := sshSecretBackendRoleBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing ssh role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading role from %q", path)
	role, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read role from %q", path)
	if role == nil {
		log.Printf("[WARN] Role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	d.Set("name", name)
	d.Set("backend", backend)
	d.Set("key_type", role.Data["key_type"])
	d.Set("allow_bare_domains", role.Data["allow_bare_domains"])
	d.Set("allow_host_certificates", role.Data["allow_host_certificates"])
	d.Set("allow_subdomains", role.Data["allow_subdomains"])
	d.Set("allow_user_certificates", role.Data["allow_user_certificates"])
	d.Set("allow_user_key_ids", role.Data["allow_user_key_ids"])
	d.Set("allowed_critical_options", role.Data["allowed_critical_options"])
	d.Set("allowed_domains", role.Data["allowed_domains"])
	d.Set("cidr_list", role.Data["cidr_list"])
	d.Set("allowed_extensions", role.Data["allowed_extensions"])
	d.Set("default_extensions", role.Data["default_extensions"])
	d.Set("default_critical_options", role.Data["default_critical_options"])
	d.Set("allowed_users", role.Data["allowed_users"])
	d.Set("default_user", role.Data["default_user"])
	d.Set("key_id_format", role.Data["key_id_format"])
	d.Set("max_ttl", role.Data["max_ttl"])
	d.Set("ttl", role.Data["ttl"])

	return nil
}

func sshSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
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

func sshSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
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

func sshRoleResourcePath(backend, name string) string {
	return strings.Trim(backend, "/") + "/roles/" + strings.Trim(name, "/")
}

func sshSecretBackendRoleNameFromPath(path string) (string, error) {
	if !sshSecretBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := sshSecretBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func sshSecretBackendRoleBackendFromPath(path string) (string, error) {
	if !sshSecretBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := sshSecretBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
