// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func userpassUserResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"backend": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Auth backend to which user will be configured.",
			ForceNew:    true,
			Default:     "userpass",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"username": {
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			Description:  "Username part of userpass.",
			ValidateFunc: provider.ValidateStringSlug,
		},
		"password": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Password part of userpass.",
			Sensitive:   true,
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		Create: userpassUserCreate,
		Read:   ReadWrapper(userpassUserRead),
		Update: userpassUserUpdate,
		Delete: userpassUserDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func userPath(backend string, username string) string {
	return fmt.Sprintf("auth/%s/users/%s", strings.Trim(backend, "/"), strings.Trim(username, "/"))
}

func usernameFromPath(userId string) string {
	return userId[strings.LastIndex(userId, "/")+1:]
}

func backendFromPath(userId string) string {
	userPath := "/users/" + usernameFromPath(userId)
	s := strings.Replace(userId, userPath, "", -1)
	return strings.Replace(s, "auth/", "", -1)
}

func userpassUserCreate(d *schema.ResourceData, meta interface{}) error {
	id := userPath(d.Get("backend").(string), d.Get("username").(string))
	d.SetId(id)
	d.MarkNewResource()

	log.Printf("[INFO] Creating new user at '%v'", id)
	return userpassUserUpdate(d, meta)
}

func userpassUserUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	data := map[string]interface{}{}

	updateTokenFields(d, data, false)

	if v, ok := d.GetOk("username"); ok {
		data["username"] = v.(string)
	}

	if v, ok := d.GetOk("password"); ok {
		data["password"] = v.(string)
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		log.Printf("[ERROR] Error writing user at '%s'", path)
		return err
	}

	log.Printf("[INFO] Saved user at '%v'", path)

	return userpassUserRead(d, meta)
}

func userpassUserRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	dt, err := client.Logical().Read(path)
	if err != nil {
		log.Printf("[ERROR] Error reading user from '%s'", path)
		return err
	}

	d.Set("username", usernameFromPath(path))
	d.Set("backend", backendFromPath(path))
	readTokenFields(d, dt)

	return nil
}

func userpassUserDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	_, err := client.Logical().Delete(d.Id())
	if err != nil {
		return err
	}
	return nil
}
