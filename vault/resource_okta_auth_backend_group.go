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

func oktaAuthBackendGroupResource() *schema.Resource {
	return &schema.Resource{
		Create: oktaAuthBackendGroupWrite,
		Read:   oktaAuthBackendGroupRead,
		Update: oktaAuthBackendGroupWrite,
		Delete: oktaAuthBackendGroupDelete,
		Exists: oktaAuthBackendGroupExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path to the Okta auth backend",
			},

			"group_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the Okta group",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					// No comma as it'll become part of a comma separate list
					if strings.Contains(value, ",") {
						errs = append(errs, errors.New("group name cannot contain ','"))
					}
					return
				},
			},

			"policies": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "Policies to associate with this group",
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

func oktaAuthBackendGroupWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	groupName := d.Get("group_name").(string)

	log.Printf("[DEBUG] Writing group %s to Okta auth backend %s", groupName, path)

	var policiesString []string
	if policies, ok := d.GetOk("policies"); ok {
		policiesString = util.ToStringArray(policies.(*schema.Set).List())
	} else {
		policiesString = []string{}
	}

	group := oktaGroup{
		Name:     groupName,
		Policies: policiesString,
	}
	if err := updateOktaGroup(client, path, group); err != nil {
		return fmt.Errorf("unable to write group %s to Vault: %s", groupName, err)
	}

	d.SetId(oktaAuthBackendGroupID(path, groupName))

	return oktaAuthBackendGroupRead(d, meta)
}

func oktaAuthBackendGroupRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	backend, err := oktaAuthBackendGroupPathFromID(id)
	if err != nil {
		return fmt.Errorf("invalid id %q for Okta auth backend group: %s", id, err)
	}
	groupName, err := oktaAuthBackendGroupNameFromID(id)
	if err != nil {
		return fmt.Errorf("invalid id %q for Okta auth backend group: %s", id, err)
	}

	log.Printf("[DEBUG] Reading group %s from Okta auth backend %s", groupName, backend)

	present, err := isOktaGroupPresent(client, backend, groupName)

	if err != nil {
		return fmt.Errorf("unable to read group %s from Vault: %s", groupName, err)
	}

	if !present {
		// Group not found, so remove this resource
		d.SetId("")
		return nil
	}

	group, err := readOktaGroup(client, backend, groupName)
	if err != nil {
		return fmt.Errorf("unable to update group %s from Vault: %s", groupName, err)
	}

	d.Set("policies", group.Policies)
	d.Set("group_name", group.Name)
	d.Set("path", backend)

	return nil
}

func oktaAuthBackendGroupDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	group := d.Get("group_name").(string)

	log.Printf("[DEBUG] Deleting group %s from Okta auth backend %s", group, path)

	if err := deleteOktaGroup(client, path, group); err != nil {
		return fmt.Errorf("unable to delete group %s from Vault: %s", group, err)
	}

	d.SetId("")

	return nil
}

func oktaAuthBackendGroupExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	id := d.Id()

	backend, err := oktaAuthBackendGroupPathFromID(id)
	if err != nil {
		return false, fmt.Errorf("invalid id %q for Okta auth backend group: %s", id, err)
	}
	groupName, err := oktaAuthBackendGroupNameFromID(id)
	if err != nil {
		return false, fmt.Errorf("invalid id %q for Okta auth backend group: %s", id, err)
	}

	log.Printf("[DEBUG] Checking if Okta group %q exists", groupName)
	present, err := isOktaGroupPresent(client, backend, groupName)
	if err != nil {
		return false, fmt.Errorf("error checking for existence of Okta group %q: %s", groupName, err)
	}
	log.Printf("[DEBUG] Checked if Okta group %q exists", groupName)

	return present, nil
}

func oktaAuthBackendGroupID(path, groupName string) string {
	return strings.Join([]string{path, groupName}, "/")
}

func oktaAuthBackendGroupPathFromID(id string) (string, error) {
	var parts = strings.SplitN(id, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("Expected 2 parts in ID '%s'", id)
	}
	return parts[0], nil
}

func oktaAuthBackendGroupNameFromID(id string) (string, error) {
	var parts = strings.SplitN(id, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("Expected 2 parts in ID '%s'", id)
	}
	return parts[1], nil
}
