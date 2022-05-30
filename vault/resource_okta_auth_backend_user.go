package vault

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func oktaAuthBackendUserResource() *schema.Resource {
	return &schema.Resource{
		Create: oktaAuthBackendUserWrite,
		Read:   oktaAuthBackendUserRead,
		Update: oktaAuthBackendUserWrite,
		Delete: oktaAuthBackendUserDelete,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path to the Okta auth backend",
			},

			"username": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the user within Okta",
			},

			"groups": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "Groups within the Okta auth backend to associate with this user",
				Elem: &schema.Schema{
					Type: schema.TypeString,
					ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
						value := v.(string)
						// No comma as it'll become part of a comma separate list
						if strings.Contains(value, ",") {
							errs = append(errs, errors.New("group cannot contain ','"))
						}
						return
					},
				},
				Set: schema.HashString,
			},

			"policies": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "Policies to associate with this user",
				Elem: &schema.Schema{
					Type: schema.TypeString,
					ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
						value := v.(string)
						// No comma as it'll become part of a comma separate list
						if strings.Contains(value, ",") {
							errs = append(errs, errors.New("policy cannot contain ','"))
						}
						return
					},
				},
				Set: schema.HashString,
			},
		},
	}
}

func oktaAuthBackendUserWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	username := d.Get("username").(string)
	path := d.Get("path").(string)

	log.Printf("[DEBUG] Writing user %s to Okta auth backend %s", username, path)

	var groupsString []string
	if groups, ok := d.GetOk("groups"); ok {
		groupsString = util.ToStringArray(groups.(*schema.Set).List())
	} else {
		groupsString = []string{}
	}

	var policiesString []string
	if policies, ok := d.GetOk("policies"); ok {
		policiesString = util.ToStringArray(policies.(*schema.Set).List())
	} else {
		policiesString = []string{}
	}

	user := oktaUser{
		Username: username,
		Groups:   groupsString,
		Policies: policiesString,
	}
	if err := updateOktaUser(client, path, user); err != nil {
		return fmt.Errorf("unable to update user %s in Vault: %s", username, err)
	}

	d.SetId(fmt.Sprintf("%s/%s", path, username))

	return oktaAuthBackendUserRead(d, meta)
}

func oktaAuthBackendUserRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	username := d.Get("username").(string)

	log.Printf("[DEBUG] Reading user %s from Okta auth backend %s", username, path)

	present, err := isOktaUserPresent(client, path, username)

	if err != nil {
		return fmt.Errorf("unable to read user %s in Vault: %s", username, err)
	}

	if !present {
		// User not found, so remove this resource
		d.SetId("")
		return nil
	}

	user, err := readOktaUser(client, path, username)
	if err != nil {
		return fmt.Errorf("unable to update user %s from Vault: %s", username, err)
	}

	d.Set("groups", user.Groups)
	d.Set("policies", user.Policies)

	return nil
}

func oktaAuthBackendUserDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	username := d.Get("username").(string)

	log.Printf("[DEBUG] Deleting user %s from Okta auth backend %s", username, path)

	if err := deleteOktaUser(client, path, username); err != nil {
		return fmt.Errorf("unable to delete user %s from Vault: %s", username, path)
	}

	d.SetId("")

	return nil
}
