package vault

import (
	"errors"
	"fmt"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"log"
	"strings"
)

func oktaAuthBackendGroupResource() *schema.Resource {
	return &schema.Resource{
		Create: oktaAuthBackendGroupWrite,
		Read:   oktaAuthBackendGroupRead,
		Update: oktaAuthBackendGroupWrite,
		Delete: oktaAuthBackendGroupDelete,

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
					if strings.Contains(value, ",") || strings.Contains(value, "/") {
						errs = append(errs, errors.New("group name cannot contain ',' or '/'"))
					}
					return
				},
			},

			"policies": {
				Type:        schema.TypeList,
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
		policiesString = toStringArray(policies.([]interface{}))
	} else {
		policiesString = []string{}
	}

	group := oktaGroup{
		Name:     groupName,
		Policies: policiesString,
	}
	if err := updateOktaGroup(client, path, group); err != nil {
		return fmt.Errorf("Unable to write group %s to Vault: %s", groupName, err)
	}

	d.SetId(fmt.Sprintf("%s/%s", path, group))

	return nil
}

func oktaAuthBackendGroupRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	group := d.Get("group_name").(string)

	log.Printf("[DEBUG] Reading group %s from Okta auth backend %s", group, path)

	present, err := isOktaGroupPresent(client, path, group)

	if err != nil {
		return fmt.Errorf("Unable to read group %s from Vault: %s", group, err)
	}

	if !present {
		// Group not found, so remove this resource
		d.SetId("")
	}

	return nil
}

func oktaAuthBackendGroupDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	group := d.Get("group_name").(string)

	log.Printf("[DEBUG] Deleting group %s from Okta auth backend %s", group, path)

	if err := deleteOktaGroup(client, path, group); err != nil {
		return fmt.Errorf("Unable to delete group %s from Vault: %s", group, err)
	}

	d.SetId("")

	return nil
}
