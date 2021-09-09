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
	adSecretBackendFromPathRegex         = regexp.MustCompile("^(.+)/roles/.+$")
	adSecretBackendRoleNameFromPathRegex = regexp.MustCompile("^.+/roles/(.+$)")
)

func adSecretBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"backend": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "The mount path for the AD backend.",
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
		"last_vault_rotation": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Last time Vault rotated this service account's password.",
		},
		"password_last_set": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Last time Vault set this service account's password.",
		},
		"service_account_name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `The username/logon name for the service account with which this role will be associated.`,
		},
		"ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: `In seconds, the default password time-to-live.`,
		},
	}
	return &schema.Resource{
		Create: createRoleResource,
		Update: updateRoleResource,
		Read:   readRoleResource,
		Delete: deleteRoleResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func createRoleResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	backend := d.Get("backend").(string)
	role := d.Get("role").(string)
	rolePath := fmt.Sprintf("%s/roles/%s", backend, role)

	log.Printf("[DEBUG] Creating %q", rolePath)

	data := map[string]interface{}{}
	if v, ok := d.GetOkExists("service_account_name"); ok {
		data["service_account_name"] = v
	}

	if v, ok := d.GetOkExists("ttl"); ok {
		data["ttl"] = v
	}

	log.Printf("[DEBUG] Writing %q", rolePath)
	if _, err := client.Logical().Write(rolePath, data); err != nil {
		return fmt.Errorf("error writing %q: %s", rolePath, err)
	}
	d.SetId(rolePath)
	log.Printf("[DEBUG] Wrote %q", rolePath)
	return readRoleResource(d, meta)
}

func readRoleResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	rolePath := d.Id()
	log.Printf("[DEBUG] Reading %q", rolePath)

	roleName, err := adSecretBackendRoleNameFromPath(rolePath)
	if err != nil {
		return fmt.Errorf("invalid role ID %q: %s", rolePath, err)
	}
	d.Set("role", roleName)

	backend, err := adSecretBackendFromPath(rolePath)
	if err != nil {
		return fmt.Errorf("invalid role ID %q: %s", rolePath, err)
	}
	d.Set("backend", backend)

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

	if val, ok := resp.Data["service_account_name"]; ok {
		if err := d.Set("service_account_name", val); err != nil {
			return fmt.Errorf("error setting state key 'service_account_name': %s", err)
		}
	}

	if val, ok := resp.Data["ttl"]; ok {
		if err := d.Set("ttl", val); err != nil {
			return fmt.Errorf("error setting state key 'ttl': %s", err)
		}
	}

	if val, ok := resp.Data["last_vault_rotation"]; ok {
		if err := d.Set("last_vault_rotation", val); err != nil {
			return fmt.Errorf("error setting state key 'last_vault_rotation': %s", err)
		}
	}

	if val, ok := resp.Data["password_last_set"]; ok {
		if err := d.Set("password_last_set", val); err != nil {
			return fmt.Errorf("error setting state key 'password_last_set': %s", err)
		}
	}
	return nil
}

func updateRoleResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	rolePath := d.Id()
	log.Printf("[DEBUG] Updating %q", rolePath)

	data := map[string]interface{}{}
	if raw, ok := d.GetOk("service_account_name"); ok {
		data["service_account_name"] = raw
	}
	if raw, ok := d.GetOk("ttl"); ok {
		data["ttl"] = raw
	}
	if _, err := client.Logical().Write(rolePath, data); err != nil {
		return fmt.Errorf("error updating template auth backend role %q: %s", rolePath, err)
	}
	log.Printf("[DEBUG] Updated %q", rolePath)
	return readRoleResource(d, meta)
}

func deleteRoleResource(d *schema.ResourceData, meta interface{}) error {
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

func adSecretBackendRoleNameFromPath(path string) (string, error) {
	if !adSecretBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := adSecretBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func adSecretBackendFromPath(path string) (string, error) {
	if !adSecretBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := adSecretBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
