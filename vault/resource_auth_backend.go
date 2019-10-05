package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func authBackendResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: authBackendWrite,
		Delete: authBackendDelete,
		Read:   authBackendRead,
		Update: authBackendUpdate,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		MigrateState: resourceAuthBackendMigrateState,

		Schema: map[string]*schema.Schema{
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the auth backend",
			},

			"path": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				ForceNew:     true,
				Description:  "path to mount the backend. This defaults to the type.",
				ValidateFunc: validateNoTrailingSlash,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},

			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "Default lease duration in seconds",
			},

			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "Maximum possible lease duration in seconds",
			},

			"listing_visibility": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies whether to show this mount in the UI-specific listing endpoint",
			},

			"local": {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Description: "Specifies if the auth method is local only",
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the auth backend",
			},
		},
	}
}

func authBackendPath(path string) string {
	return "auth/" + strings.Trim(path, "/")
}

func authBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	path = authBackendPath(path)

	d.Partial(true)

	if d.HasChange("listing_visibility") {
		config := api.MountConfigInput{
			ListingVisibility: d.Get("listing_visibility").(string),
		}
		log.Printf("[DEBUG] Updating listing visibility for %q", path)
		err := client.Sys().TuneMount(path, config)
		if err != nil {
			return fmt.Errorf("error updating listing visibility for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated listing visibility for %q", path)
		d.SetPartial("listing_visibility")
	}

	if d.HasChange("default_lease_ttl_seconds") || d.HasChange("max_lease_ttl_seconds") {
		config := api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		}
		log.Printf("[DEBUG] Updating lease TTLs for %q", path)
		err := client.Sys().TuneMount(path, config)
		if err != nil {
			return fmt.Errorf("error updating mount TTLs for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated lease TTLs for %q", path)
		d.SetPartial("default_lease_ttl_seconds")
		d.SetPartial("max_lease_ttl_seconds")
	}

	if d.HasChange("description") {
		description := d.Get("description").(string)
		config := api.MountConfigInput{
			Description: &description,
		}
		log.Printf("[DEBUG] Updating description for %q", path)
		err := client.Sys().TuneMount(path, config)
		if err != nil {
			return fmt.Errorf("error updating description for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated description for %q", path)
		d.SetPartial("description")
	}

	d.Partial(false)
	return authBackendRead(d, meta)
}

func authBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	mountType := d.Get("type").(string)
	path := d.Get("path").(string)

	options := &api.EnableAuthOptions{
		Type:        mountType,
		Description: d.Get("description").(string),
		Config: api.AuthConfigInput{
			DefaultLeaseTTL:   fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:       fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
			ListingVisibility: d.Get("listing_visibility").(string),
		},
		Local: d.Get("local").(bool),
	}

	if path == "" {
		path = mountType
	}

	log.Printf("[DEBUG] Writing auth %q to Vault", path)

	if err := client.Sys().EnableAuthWithOptions(path, options); err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return authBackendRead(d, meta)
}

func authBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Deleting auth %s from Vault", path)

	if err := client.Sys().DisableAuth(path); err != nil {
		return fmt.Errorf("error disabling auth from Vault: %s", err)
	}

	return nil
}

func authBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	targetPath := d.Id()

	auths, err := client.Sys().ListAuth()

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	for path, auth := range auths {
		path = strings.TrimSuffix(path, "/")
		if path == targetPath {
			d.Set("type", auth.Type)
			d.Set("path", path)
			d.Set("description", auth.Description)
			d.Set("default_lease_ttl_seconds", auth.Config.DefaultLeaseTTL)
			d.Set("max_lease_ttl_seconds", auth.Config.MaxLeaseTTL)
			d.Set("listing_visibility", auth.Config.ListingVisibility)
			d.Set("local", auth.Local)
			d.Set("accessor", auth.Accessor)
			return nil
		}
	}

	// If we fell out here then we didn't find our Auth in the list.
	d.SetId("")
	return nil
}
