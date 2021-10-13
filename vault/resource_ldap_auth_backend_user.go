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
	ldapAuthBackendUserBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/users/.+$")
	ldapAuthBackendUserNameFromPathRegex    = regexp.MustCompile("^auth/.+/users/(.+)$")
)

func ldapAuthBackendUserResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: ldapAuthBackendUserResourceWrite,
		Update: ldapAuthBackendUserResourceWrite,
		Read:   ldapAuthBackendUserResourceRead,
		Delete: ldapAuthBackendUserResourceDelete,
		Exists: ldapAuthBackendUserResourceExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"username": {
				Type:     schema.TypeString,
				Required: true,
			},
			"policies": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"groups": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"backend": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "ldap",
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func ldapAuthBackendUserResourcePath(backend, username string) string {
	return "auth/" + strings.Trim(backend, "/") + "/users/" + strings.Trim(username, "/")
}

func ldapAuthBackendUserResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	username := d.Get("username").(string)
	path := ldapAuthBackendUserResourcePath(backend, username)

	data := map[string]interface{}{}

	if v, ok := d.GetOk("policies"); ok {
		data["policies"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("groups"); ok {
		data["groups"] = strings.Join(util.ToStringArray(v.(*schema.Set).List()), ",")
	}

	log.Printf("[DEBUG] Writing LDAP user %q", path)
	_, err := client.Logical().Write(path, data)

	d.SetId(path)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("error writing ldap user %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote LDAP user %q", path)

	return ldapAuthBackendUserResourceRead(d, meta)
}

func ldapAuthBackendUserResourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	backend, err := ldapAuthBackendUserBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for LDAP auth backend user: %s", path, err)
	}

	username, err := ldapAuthBackendUserNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for LDAP auth backend user: %s", path, err)
	}

	log.Printf("[DEBUG] Reading LDAP user %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading ldap user %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read LDAP user %q", path)

	if resp == nil {
		log.Printf("[WARN] LDAP user %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set("policies",
		schema.NewSet(
			schema.HashString, resp.Data["policies"].([]interface{})))

	groupSet := schema.NewSet(schema.HashString, []interface{}{})
	// Vault stores `groups` for an LDAP user as a string, not a list. We explicitly check
	// for an empty string here because without it, there exists a logical mismatch between
	// an empty set/list and the result of creating a list by splitting on an empty string.
	if resp.Data["groups"].(string) != "" {
		for _, group := range strings.Split(resp.Data["groups"].(string), ",") {
			groupSet.Add(group)
		}
	}
	d.Set("groups", groupSet)

	d.Set("backend", backend)
	d.Set("username", username)

	return nil

}

func ldapAuthBackendUserResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting LDAP user %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting ldap user %q", path)
	}
	log.Printf("[DEBUG] Deleted LDAP user %q", path)

	return nil
}

func ldapAuthBackendUserResourceExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Checking if LDAP user %q exists", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking for existence of ldap user %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if LDAP user %q exists", path)

	return resp != nil, nil
}

func ldapAuthBackendUserNameFromPath(path string) (string, error) {
	if !ldapAuthBackendUserNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no user found")
	}
	res := ldapAuthBackendUserNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func ldapAuthBackendUserBackendFromPath(path string) (string, error) {
	if !ldapAuthBackendUserBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := ldapAuthBackendUserBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
