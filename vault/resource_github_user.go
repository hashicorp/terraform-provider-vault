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

func githubUserResource() *schema.Resource {
	return &schema.Resource{
		Create: githubUserCreate,
		Read:   ReadWrapper(githubUserRead),
		Update: githubUserUpdate,
		Delete: githubUserDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Auth backend to which user mapping will be congigured.",
				ForceNew:    true,
				Default:     "github",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"policies": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Policies to be assigned to this user.",
			},
			"user": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "GitHub user name.",
			},
		},
	}
}

func githubUserCreate(d *schema.ResourceData, meta interface{}) error {
	id := githubMapId(d.Get("backend").(string), d.Get("user").(string), "users")
	d.SetId(id)
	d.MarkNewResource()

	log.Printf("[INFO] Creating new github user map at '%v'", id)
	return githubUserUpdate(d, meta)
}

func githubUserUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	data := map[string]interface{}{}
	data["key"] = d.Get("user").(string)
	if v, ok := d.GetOk("policies"); ok {
		vs := expandStringSlice(v.([]interface{}))
		data["value"] = strings.Join(vs, ",")
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return err
	}

	log.Printf("[INFO] Saved github user map at '%v'", path)

	return githubUserRead(d, meta)
}

func githubUserRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	dt, err := client.Logical().Read(path)
	if err != nil {
		log.Printf("[ERROR] error when reading github user mapping from '%s'", path)
		return err
	}

	if v, ok := dt.Data["key"]; ok {
		d.Set("user", v.(string))
	} else {
		return fmt.Errorf("github user information not found at path: '%v'", d.Id())
	}

	if v, ok := dt.Data["value"]; ok {
		policies := flattenCommaSeparatedStringSlice(v.(string))
		if err := d.Set("policies", policies); err != nil {
			return err
		}
	}

	d.Set("backend", githubMappingPath(d.Id(), "users"))

	return nil
}

func githubUserDelete(d *schema.ResourceData, meta interface{}) error {
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
