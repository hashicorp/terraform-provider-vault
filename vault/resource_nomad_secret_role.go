package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

var (
	nomadSecretBackendFromRolePathRegex     = regexp.MustCompile("^(.+)/role/.+$")
	nomadSecretBackendRoleNameFromPathRegex = regexp.MustCompile("^.+/role/(.+$)")
)

func nomadSecretBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"backend": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "The mount path for the Nomad backend.",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"role": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `Name of the role.`,
			ForceNew:    true,
		},
		"global": {
			Type:        schema.TypeBool,
			Computed:    true,
			Optional:    true,
			Description: `Specifies if the token should be global.`,
		},
		"policies": {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Computed:    true,
			Optional:    true,
			Description: `Comma separated list of Nomad policies the token is going to be created against. These need to be created beforehand in Nomad.`,
		},
		"type": {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: `Specifies the type of token to create when using this role. Valid values are "client" or "management".`,
		},
	}
	return &schema.Resource{
		Create: createNomadRoleResource,
		Update: updateNomadRoleResource,
		Read:   readNomadRoleResource,
		Delete: deleteNomadRoleResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func createNomadRoleResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	backend := d.Get("backend").(string)
	role := d.Get("role").(string)
	roleType := d.Get("type").(string)

	if roleType == "" {
		roleType = "client"
	}

	rolePath := fmt.Sprintf("%s/role/%s", backend, role)

	log.Printf("[DEBUG] Creating %q", rolePath)

	data := map[string]interface{}{}
	data["type"] = roleType

	if v, ok := d.GetOkExists("global"); ok {
		data["global"] = v
	}

	// Policies are required if role type is 'client', so setting up
	// to enforce that here.
	if v, ok := d.GetOkExists("policies"); ok {
		if roleType == "client" {
			data["policies"] = v
		}
	}

	if roleType == "client" && data["policies"] == nil {
		return fmt.Errorf("error creating role %s: policies are required when role type is 'client'", role)
	}

	// Policies not supported when role type is 'management'
	if roleType == "management" && data["policies"] != nil {
		return fmt.Errorf("error creating role %s: policies should be empty when using management tokens", role)
	}

	log.Printf("[DEBUG] Writing %q", rolePath)
	if _, err := client.Logical().Write(rolePath, data); err != nil {
		return fmt.Errorf("error writing %q: %s", rolePath, err)
	}
	d.SetId(rolePath)
	log.Printf("[DEBUG] Wrote %q", rolePath)
	return readNomadRoleResource(d, meta)
}

func readNomadRoleResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	rolePath := d.Id()
	log.Printf("[DEBUG] Reading %q", rolePath)

	backend, err := nomadSecretBackendFromRolePath(rolePath)
	if err != nil {
		return fmt.Errorf("invalid role ID for backend %q: %s", rolePath, err)
	}
	d.Set("backend", backend)

	roleName, err := nomadSecretBackendRoleNameFromPath(rolePath)
	if err != nil {
		return fmt.Errorf("invalid role ID %q: %s", rolePath, err)
	}
	d.Set("role", roleName)

	resp, err := client.Logical().Read(rolePath)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", rolePath, err)
	}
	log.Printf("[DEBUG] Read %q", rolePath)

	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", rolePath)
		d.SetId("")
		return nil
	}

	if val, ok := resp.Data["global"]; ok {
		if err := d.Set("global", val); err != nil {
			return fmt.Errorf("error setting state key 'global': %s", err)
		}
	}

	if val, ok := resp.Data["policies"]; ok {
		if err := d.Set("policies", val); err != nil {
			return fmt.Errorf("error setting state key 'policies': %s", err)
		}
	}

	if val, ok := resp.Data["type"]; ok {
		if err := d.Set("type", val); err != nil {
			return fmt.Errorf("error setting state key 'type': %s", err)
		}
	}

	return nil
}

func updateNomadRoleResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	rolePath := d.Id()
	roleType := d.Get("type").(string)
	if roleType == "" {
		roleType = "client"
	}

	roleName, err := nomadSecretBackendRoleNameFromPath(rolePath)
	if err != nil {
		return fmt.Errorf("invalid role ID %q: %s", rolePath, err)
	}

	log.Printf("[DEBUG] Updating %q", rolePath)

	data := map[string]interface{}{}
	data["type"] = roleType

	if raw, ok := d.GetOk("global"); ok {
		data["global"] = raw
	}
	if raw, ok := d.GetOk("policies"); ok {
		if roleType == "client" {
			data["policies"] = raw
		}
	}

	if roleType == "client" && data["policies"] == "" {
		return fmt.Errorf("error updating role %s: policies are required when role type is 'client'", roleName)
	}

	if _, err := client.Logical().Write(rolePath, data); err != nil {
		return fmt.Errorf("error updating role %q: %s", rolePath, err)
	}
	log.Printf("[DEBUG] Updated %q", rolePath)
	return readNomadRoleResource(d, meta)
}

func deleteNomadRoleResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	rolePath := d.Id()
	log.Printf("[DEBUG] Deleting %q", rolePath)

	if _, err := client.Logical().Delete(rolePath); err != nil && !util.Is404(err) {
		return fmt.Errorf("error deleting %q: %s", rolePath, err)
	} else if err != nil {
		log.Printf("[DEBUG] %q not found, removing from state", rolePath)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted template auth backend role %q", rolePath)
	return nil
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

func nomadSecretBackendFromRolePath(path string) (string, error) {
	if !nomadSecretBackendFromRolePathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := nomadSecretBackendFromRolePathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
