package vault

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func oktaAuthBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: oktaAuthBackendWrite,
		Delete: oktaAuthBackendDelete,
		Read:   oktaAuthBackendRead,
		Update: oktaAuthBackendUpdate,

		Schema: map[string]*schema.Schema{

			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "path to mount the backend",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.HasSuffix(value, "/") {
						errs = append(errs, errors.New("cannot write to a path ending in '/'"))
					}
					return
				},
			},

			"description": {
				Type:        schema.TypeString,
				Required:    false,
				ForceNew:    true,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"organization": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Optional:    false,
				Description: "The Okta organization. This will be the first part of the url https://XXX.okta.com.",
			},

			"token": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The Okta API token. This is required to query Okta for user group membership. If this is not supplied only locally configured groups will be enabled.",
			},

			"base_url": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The Okta url. Examples: oktapreview.com, okta.com (default)",
			},

			"ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Duration after which authentication will be expired",
			},

			"max_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Maximum duration after which authentication will be expired",
			},

			"group": {
				Type:     schema.TypeSet,
				Required: false,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"group_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Name of the Okta group",
							ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
								value := v.(string)
								// No comma as it'll become part of a comma separate list
								if strings.Contains(value, ",") || strings.Contains(value, "/") {
									errs = append(errs, errors.New("group cannot contain ',' or '/'"))
								}
								return
							},
						},

						"policies": {
							Type:        schema.TypeList,
							Required:    true,
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
				},
			},

			"user": {
				Type:     schema.TypeSet,
				Required: false,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"groups": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "Groups within the Okta auth backend to associate with this user",
							Elem: &schema.Schema{
								Type: schema.TypeString,
								ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
									value := v.(string)
									// No comma as it'll become part of a comma separate list
									if strings.Contains(value, ",") || strings.Contains(value, "/") {
										errs = append(errs, errors.New("group cannot contain ',' or '/'"))
									}
									return
								},
							},
						},

						"username": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Name of the user within Okta",
							ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
								value := v.(string)
								if strings.Contains(value, "/") {
									errs = append(errs, errors.New("user cannot contain '/'"))
								}
								return
							},
						},

						"policies": {
							Type:        schema.TypeList,
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
						},
					},
				},
			},
		},
	}
}

func oktaAuthBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	authType := "okta"
	desc := d.Get("description").(string)
	path := d.Get("path").(string)

	log.Printf("[DEBUG] Writing auth %s to Vault", authType)

	var err error

	if path == "" {
		path = authType
		err = d.Set("path", authType)
		if err != nil {
			return fmt.Errorf("unable to set state: %s", err)
		}
	}

	err = client.Sys().EnableAuth(path, authType, desc)

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return oktaAuthBackendUpdate(d, meta)
}

func oktaAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Deleting auth %s from Vault", path)

	err := client.Sys().DisableAuth(path)

	if err != nil {
		return fmt.Errorf("error disabling auth from Vault: %s", err)
	}

	return nil
}

func oktaAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	auths, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	configuredPath := d.Id() + "/"

	for path, auth := range auths {

		if auth.Type == "okta" && path == configuredPath {
			return nil
		}
	}

	// If we fell out here then we didn't find our Auth in the list.
	d.SetId("")
	return nil
}

func oktaAuthBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	configuration := map[string]interface{}{
		"base_url":     d.Get("base_url"),
		"organization": d.Get("organization"),
		"token":        d.Get("token"),
	}

	if ttl, ok := d.GetOk("ttl"); ok {
		configuration["ttl"] = ttl
	}

	if maxTtl, ok := d.GetOk("max_ttl"); ok {
		configuration["max_ttl"] = maxTtl
	}

	_, err := client.Logical().Write(oktaConfigEndpoint(path), configuration)
	if err != nil {
		return fmt.Errorf("error updating configuration to Vault for path %s: %s", path, err)
	}

	if d.HasChange("group") {
		oldValue, newValue := d.GetChange("group")

		err = oktaAuthUpdateGroups(client, path, oldValue, newValue)
		if err != nil {
			return err
		}
	}

	if d.HasChange("user") {
		oldValue, newValue := d.GetChange("user")

		err = oktaAuthUpdateUsers(client, path, oldValue, newValue)
		if err != nil {
			return err
		}
	}

	return nil
}

func oktaAuthUpdateGroups(client *api.Client, path string, oldValue, newValue interface{}) error {
	groupsToDelete := onlyInFirstList(toStringList(oldValue, "group_name"), toStringList(newValue, "group_name"))

	for _, groupName := range groupsToDelete {
		log.Printf("[DEBUG] Removing Okta group %s from Vault", groupName)
		if err := deleteOktaGroup(client, path, groupName); err != nil {
			return fmt.Errorf("error removing group %s to Vault for path %s: %s", groupName, path, err)
		}
	}

	vL := newValue.(*schema.Set).List()
	for _, v := range vL {
		groupMapping := v.(map[string]interface{})
		groupName := groupMapping["group_name"].(string)

		log.Printf("[DEBUG] Adding Okta group %s to Vault", groupName)

		group := oktaGroup{
			Name:     groupName,
			Policies: toStringArray(groupMapping["policies"].([]interface{})),
		}

		if err := updateOktaGroup(client, path, group); err != nil {
			return fmt.Errorf("Error updating group %s mapping to Vault for path %s: %s", group.Name, path, err)
		}
	}

	return nil
}

func oktaAuthUpdateUsers(client *api.Client, path string, oldValue, newValue interface{}) error {
	usersToDelete := onlyInFirstList(toStringList(oldValue, "username"), toStringList(newValue, "username"))

	for _, userName := range usersToDelete {
		log.Printf("[DEBUG] Removing Okta user %s from Vault", userName)
		if err := deleteOktaUser(client, path, userName); err != nil {
			return fmt.Errorf("error removing user %s mapping to Vault for path %s: %s", userName, path, err)
		}
	}

	vL := newValue.(*schema.Set).List()
	for _, v := range vL {
		userMapping := v.(map[string]interface{})
		userName := userMapping["username"].(string)

		log.Printf("[DEBUG] Adding Okta user %s to Vault", userName)

		user := oktaUser{
			Username: userName,
			Policies: toStringArray(userMapping["policies"].([]interface{})),
			Groups:   toStringArray(userMapping["groups"].([]interface{})),
		}

		if err := updateOktaUser(client, path, user); err != nil {
			return fmt.Errorf("error updating user %s mapping to Vault for path %s: %s", user.Username, path, err)
		}

	}

	return nil
}
