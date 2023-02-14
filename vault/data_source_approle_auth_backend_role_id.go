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

func approleAuthBackendRoleIDDataSource() *schema.Resource {
	return &schema.Resource{
		Read: ReadWrapper(approleAuthBackendRoleIDRead),

		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role.",
				ForceNew:    true,
			},
			"role_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The RoleID of the role.",
			},
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "approle",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func approleAuthBackendRoleIDRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := approleAuthBackendRolePath(d.Get("backend").(string), d.Get("role_name").(string))

	log.Printf("[DEBUG] Reading AppRole auth backend role %q RoleID", path)
	resp, err := client.Logical().Read(path + "/role-id")
	if err != nil {
		return fmt.Errorf("error reading AppRole auth backend role %q RoleID: %s", path, err)
	}
	log.Printf("[DEBUG] Read AppRole auth backend role %q RoleID", path)

	if resp == nil {
		d.SetId("")
		return nil
	}
	d.SetId(path + "/role-id")
	d.Set("role_id", resp.Data["role_id"])

	return nil
}
