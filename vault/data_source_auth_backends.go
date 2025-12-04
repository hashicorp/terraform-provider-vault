// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func authBackendsDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(authBackendsDataSourceRead),
		Schema: map[string]*schema.Schema{
			consts.FieldPaths: {
				Type:        schema.TypeList,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "The auth backend mount points.",
			},
			consts.FieldType: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The type of the auth backend.",
			},
			consts.FieldAccessors: {
				Type:        schema.TypeList,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "The accessors of the auth backends.",
			},
		},
	}
}

func authBackendsDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	targetType := d.Get("type").(string)

	auths, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	var paths, accessors []string

	for path, auth := range auths {

		path = strings.TrimSuffix(path, "/")

		if targetType == "" {
			paths = append(paths, path)
			accessors = append(accessors, auth.Accessor)
		} else if auth.Type == targetType {
			paths = append(paths, path)
			accessors = append(accessors, auth.Accessor)
		}
	}

	// Single instance data source - defaulting ID to 'default'
	d.SetId("default")
	d.Set(consts.FieldPaths, paths)
	d.Set(consts.FieldType, targetType)
	d.Set(consts.FieldAccessors, accessors)

	return nil
}
