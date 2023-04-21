// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func authBackendsDataSource() *schema.Resource {
	return &schema.Resource{
		Read: ReadWrapper(authBackendsDataSourceRead),
		Schema: map[string]*schema.Schema{
			"paths": {
				Type:        schema.TypeList,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "The auth backend mount points.",
			},
			"type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the auth backend.",
			},
			"accessors": {
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
			// we do this to make test assertions easier
			// this is not required
			sort.Strings(paths)
		} else if auth.Type == targetType {
			paths = append(paths, path)
			accessors = append(accessors, auth.Accessor)
		}
	}

	// Single instance data source - defaulting ID to 'default'
	d.SetId("default")
	d.Set("paths", paths)
	d.Set("type", targetType)
	d.Set("accessors", accessors)

	// If we fell out here then we didn't find our Auth in the list.
	return nil
}
