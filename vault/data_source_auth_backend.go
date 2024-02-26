// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func authBackendDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(authBackendDataSourceRead),
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The auth backend mount point.",
			},
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The name of the auth backend.",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The description of the auth backend.",
			},
			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Default lease duration in seconds",
			},
			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Maximum possible lease duration in seconds",
			},
			"listing_visibility": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Specifies whether to show this mount in the UI-specific listing endpoint.",
			},
			"local": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Specifies if the auth method is local only",
			},
			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the auth backend.",
			},
		},
	}
}

func authBackendDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get("path").(string)

	auth, err := mountutil.GetAuthMount(context.Background(), client, path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	path = strings.TrimSuffix(path, "/")
	d.SetId(path)

	if err := d.Set("type", auth.Type); err != nil {
		return err
	}
	if err := d.Set("description", auth.Description); err != nil {
		return err
	}
	if err := d.Set("accessor", auth.Accessor); err != nil {
		return err
	}
	if err := d.Set("default_lease_ttl_seconds", auth.Config.DefaultLeaseTTL); err != nil {
		return err
	}
	if err := d.Set("max_lease_ttl_seconds", auth.Config.MaxLeaseTTL); err != nil {
		return err
	}
	if err := d.Set("listing_visibility", auth.Config.ListingVisibility); err != nil {
		return err
	}
	if err := d.Set("local", auth.Local); err != nil {
		return err
	}

	return nil
}
