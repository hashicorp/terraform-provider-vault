package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	awsAuthBackendRoleTagBlacklistBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/config/tidy/roletag-blacklist$")
)

func awsAuthBackendRoleTagBlacklistResource() *schema.Resource {
	return &schema.Resource{
		Create: awsAuthBackendRoleTagBlacklistWrite,
		Read:   awsAuthBackendRoleTagBlacklistRead,
		Update: awsAuthBackendRoleTagBlacklistWrite,
		Delete: awsAuthBackendRoleTagBlacklistDelete,
		Exists: awsAuthBackendRoleTagBlacklistExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"safety_buffer": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The amount of extra time that must have passed beyond the roletag expiration, before it's removed from backend storage.",
				Default:     259200,
			},
			"disable_periodic_tidy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If true, disables the periodic tidying of the roletag blacklist entries.",
				Default:     false,
			},
		},
	}
}

func awsAuthBackendRoleTagBlacklistWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	data := map[string]interface{}{
		"safety_buffer":         d.Get("safety_buffer").(int),
		"disable_periodic_tidy": d.Get("disable_periodic_tidy").(bool),
	}

	path := awsAuthBackendRoleTagBlacklistPath(backend)

	log.Printf("[DEBUG] Configuring AWS auth backend roletag blacklist %q", path)
	_, err := client.Logical().Write(path, data)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error configuring AWS auth backend roletag blacklist %q: %s", path, err)
	}
	log.Printf("[DEBUG] Configured AWS backend roletag blacklist %q", path)

	d.SetId(path)

	return awsAuthBackendRoleTagBlacklistRead(d, meta)
}

func awsAuthBackendRoleTagBlacklistRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	backend, err := awsAuthBackendRoleTagBlacklistBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing invalid ID %q from state", d.Id())
		d.SetId("")
		return fmt.Errorf("Invalid path %q for AWS auth backend roletag blacklist: %s", path, err)
	}

	log.Printf("[DEBUG] Reading roletag blacklist %q from AWS auth backend", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("Error reading AWS auth backend roletag blacklist %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read roletag blacklist %q from AWS auth backend", path)
	if resp == nil {
		log.Printf("[WARN] AWS auth backend roletag blacklist %q not found, removing it from state", path)
		d.SetId("")
		return nil
	}

	d.Set("safety_buffer", resp.Data["safety_buffer"])
	d.Set("disable_periodic_tidy", resp.Data["disable_periodic_tidy"])
	d.Set("backend", backend)

	return nil
}

func awsAuthBackendRoleTagBlacklistDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Removing roletag blacklist %q from AWS auth backend", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting AWS auth backend roletag blacklist %q: %s", path, err)
	}
	log.Printf("[DEBUG] Removed roletag blacklist %q from AWS auth backend", path)

	return nil
}

func awsAuthBackendRoleTagBlacklistExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Checking if roletag blacklist %q exists in AWS auth backend", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("Error checking for existence of AWS auth backend roletag blacklist %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if roletag blacklist %q exists in AWS auth backend", path)
	return resp != nil, nil
}

func awsAuthBackendRoleTagBlacklistPath(backend string) string {
	return "auth/" + strings.Trim(backend, "/") + "/config/tidy/roletag-blacklist"
}

func awsAuthBackendRoleTagBlacklistBackendFromPath(path string) (string, error) {
	if !awsAuthBackendRoleTagBlacklistBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := awsAuthBackendRoleTagBlacklistBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
