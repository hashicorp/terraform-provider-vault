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
	awsAuthBackendIdentityWhitelistBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/config/tidy/identity-whitelist$")
)

func awsAuthBackendIdentityWhitelistResource() *schema.Resource {
	return &schema.Resource{
		Create: awsAuthBackendIdentityWhitelistWrite,
		Read:   awsAuthBackendIdentityWhitelistRead,
		Update: awsAuthBackendIdentityWhitelistWrite,
		Delete: awsAuthBackendIdentityWhitelistDelete,
		Exists: awsAuthBackendIdentityWhitelistExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "aws",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"safety_buffer": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The amount of extra time that must have passed beyond the roletag expiration, before it's removed from backend storage.",
			},
			"disable_periodic_tidy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If true, disables the periodic tidying of the identiy whitelist entries.",
			},
		},
	}
}

func awsAuthBackendIdentityWhitelistWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	data := map[string]interface{}{}

	if v, ok := d.GetOkExists("safety_buffer"); ok {
		data["safety_buffer"] = v
	}
	if v, ok := d.GetOkExists("disable_periodic_tidy"); ok {
		data["disable_periodic_tidy"] = v
	}

	path := awsAuthBackendIdentityWhitelistPath(backend)

	log.Printf("[DEBUG] Configuring AWS auth backend identity whitelist %q", path)
	_, err := client.Logical().Write(path, data)

	d.SetId(path)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("error configuring AWS auth backend identity whitelist %q: %s", path, err)
	}
	log.Printf("[DEBUG] Configured AWS backend identity whitelist %q", path)

	return awsAuthBackendIdentityWhitelistRead(d, meta)
}

func awsAuthBackendIdentityWhitelistRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	backend, err := awsAuthBackendIdentityWhitelistBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for AWS auth backend identity whitelist: %s", path, err)
	}

	log.Printf("[DEBUG] Reading identity whitelist %q from AWS auth backend", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading AWS auth backend identity whitelist %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read identity whitelist %q from AWS auth backend", path)
	if resp == nil {
		log.Printf("[WARN] AWS auth backend identity whitelist %q not found, removing it from state", path)
		d.SetId("")
		return nil
	}

	d.Set("safety_buffer", resp.Data["safety_buffer"])
	d.Set("disable_periodic_tidy", resp.Data["disable_periodic_tidy"])
	d.Set("backend", backend)

	return nil
}

func awsAuthBackendIdentityWhitelistDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Removing identity whitelist %q from AWS auth backend", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting AWS auth backend identity whitelist %q: %s", path, err)
	}
	log.Printf("[DEBUG] Removed identity whitelist %q from AWS auth backend", path)

	return nil
}

func awsAuthBackendIdentityWhitelistExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Checking if identity whitelist %q exists in AWS auth backend", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking for existence of AWS auth backend identity whitelist %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if identity whitelist %q exists in AWS auth backend", path)
	return resp != nil, nil
}

func awsAuthBackendIdentityWhitelistPath(backend string) string {
	return "auth/" + strings.Trim(backend, "/") + "/config/tidy/identity-whitelist"
}

func awsAuthBackendIdentityWhitelistBackendFromPath(path string) (string, error) {
	if !awsAuthBackendIdentityWhitelistBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := awsAuthBackendIdentityWhitelistBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
