package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	nomadSecretBackendRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/role/.+$")
	nomadSecretBackendRoleNameFromPathRegex    = regexp.MustCompile("^.+/role/(.+$)")
)

func nomadSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: nomadSecretBackendRoleWrite,
		Read:   nomadSecretBackendRoleRead,
		Update: nomadSecretBackendRoleWrite,
		Delete: nomadSecretBackendRoleDelete,
		Exists: nomadSecretBackendRoleExists,
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
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				Description:   "The path of the Nomad Secret Backend the role belongs to.",
				ConflictsWith: []string{"path"},
			},
			"policies": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "List of Nomad policies to associate with this role",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"max_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum TTL for leases associated with this role, in seconds.",
				Default:     0,
			},
			"ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Specifies the TTL for this role.",
				Default:     0,
			},
			"token_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the type of token to create when using this role. Valid values are \"client\" or \"management\".",
				Default:     "client",
			},
			"local": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Indicates that the token should not be replicated globally and instead be local to the current datacenter.",
				Default:     false,
			},
		},
	}
}

func nomadSecretBackendRoleGetBackend(d *schema.ResourceData) string {
	if v, ok := d.GetOk("backend"); ok {
		return v.(string)
	} else if v, ok := d.GetOk("path"); ok {
		return v.(string)
	} else {
		return ""
	}
}

func nomadSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	backend := nomadSecretBackendRoleGetBackend(d)
	if backend == "" {
		return fmt.Errorf("No backend specified for Nomad secret backend role %s", name)
	}

	path := nomadSecretBackendRolePath(backend, name)

	policies := d.Get("policies").([]interface{})

	payload := map[string]interface{}{
		"policies": policies,
	}

	if v, ok := d.GetOkExists("max_ttl"); ok {
		payload["max_ttl"] = v
	}
	if v, ok := d.GetOkExists("ttl"); ok {
		payload["ttl"] = v
	}
	if v, ok := d.GetOkExists("token_type"); ok {
		payload["token_type"] = v
	}
	if v, ok := d.GetOkExists("local"); ok {
		payload["local"] = v
	}

	log.Printf("[DEBUG] Configuring Nomad secrets backend role at %q", path)

	if _, err := client.Logical().Write(path, payload); err != nil {
		return fmt.Errorf("error writing role configuration for %q: %s", path, err)
	}

	d.SetId(path)
	return nomadSecretBackendRoleRead(d, meta)
}

func nomadSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	name, err := nomadSecretBackendRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing nomad role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid role ID %q: %s", path, err)
	}

	backend, err := nomadSecretBackendRoleBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing nomad role %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading Nomad secrets backend role at %q", path)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading role configuration for %q: %s", path, err)
	}

	if secret == nil {
		return fmt.Errorf("resource not found")
	}

	data := secret.Data
	d.Set("name", name)
	if _, ok := d.GetOk("path"); ok {
		d.Set("path", backend)
	} else {
		d.Set("backend", backend)
	}
	d.Set("policies", data["policies"])
	d.Set("max_ttl", data["max_ttl"])
	d.Set("ttl", data["ttl"])
	d.Set("token_type", data["token_type"])
	d.Set("local", data["local"])

	return nil
}

func nomadSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Deleting Nomad backend role at %q", path)

	if _, err := client.Logical().Delete(path); err != nil {
		return fmt.Errorf("error deleting Nomad backend role at %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted Nomad backend role at %q", path)
	return nil
}

func nomadSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Checking Nomad secrets backend role at %q", path)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return false, fmt.Errorf("error reading role configuration for %q: %s", path, err)
	}

	return secret != nil, nil
}

func nomadSecretBackendRolePath(backend, name string) string {
	return strings.Trim(backend, "/") + "/role/" + name
}

func nomadSecretBackendRoleNameFromPath(path string) (string, error) {
	if !nomadSecretBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := nomadSecretBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func nomadSecretBackendRoleBackendFromPath(path string) (string, error) {
	if !nomadSecretBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := nomadSecretBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
