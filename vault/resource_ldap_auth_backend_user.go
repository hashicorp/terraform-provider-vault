package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
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
	for _, group := range strings.Split(resp.Data["groups"].(string), ",") {
		groupSet.Add(group)
	}
	d.Set("groups", groupSet)

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
