package vault

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func authBackendDataSource() *schema.Resource {
	return &schema.Resource{
		Read: authBackendDataSourceRead,
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
	client := meta.(*api.Client)

	targetPath := d.Get("path").(string)

	auths, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	for path, auth := range auths {
		path = strings.TrimSuffix(path, "/")
		if path == targetPath {
			// Compatibility with resource_auth_backend id
			d.SetId(path)
			d.Set("type", auth.Type)
			d.Set("description", auth.Description)
			d.Set("accessor", auth.Accessor)
			d.Set("default_lease_ttl_seconds", auth.Config.DefaultLeaseTTL)
			d.Set("max_lease_ttl_seconds", auth.Config.MaxLeaseTTL)
			d.Set("listing_visibility", auth.Config.ListingVisibility)
			d.Set("local", auth.Local)
			return nil
		}
	}

	// If we fell out here then we didn't find our Auth in the list.
	return nil
}
