package vault

import (
	"fmt"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"log"
	"strings"
)

func transitSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: transitSecretBackendCreate,
		Read:   transitSecretBackendRead,
		Update: transitSecretBackendUpdate,
		Delete: transitSecretBackendDelete,
		Exists: transitSecretBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path to mount the backend at.",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.HasSuffix(value, "/") {
						errs = append(errs, fmt.Errorf("path cannot end in '/'"))
					}
					return
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},
			"description": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Computed:    true,
				ForceNew:    false,
				Description: "Default lease duration for tokens and secrets in seconds",
			},
			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Computed:    true,
				ForceNew:    false,
				Description: "Maximum possible lease duration for tokens and secrets in seconds",
			},
		},
	}
}

func transitSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	description := d.Get("description").(string)
	defaultTTL := d.Get("default_lease_ttl_seconds").(int)
	maxTTL := d.Get("max_lease_ttl_seconds").(int)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Transit backend at %q", path)
	err := client.Sys().Mount(path, &api.MountInput{
		Type:        "transit",
		Description: description,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
			MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
		},
	})
	if err != nil {
		return fmt.Errorf("error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted Transit backend at %q", path)
	d.SetId(path)

	d.SetPartial("path")
	d.SetPartial("description")
	d.SetPartial("default_lease_ttl_seconds")
	d.SetPartial("max_lease_ttl_seconds")
	d.Partial(false)
	return transitSecretBackendRead(d, meta)
}

func transitSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Reading Transit backend mount %q from Vault", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading mount %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Transit backend mount %q from Vault", path)

	// the API always returns the path with a trailing slash, so let's make
	// sure we always specify it as a trailing slash.
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing backend from state.", path)
		d.SetId("")
		return nil
	}

	d.Set("path", path)
	d.Set("description", mount.Description)
	d.Set("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL)
	d.Partial(false)

	return nil
}

func transitSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	d.Partial(true)
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
	d.Partial(false)

	return pkiSecretBackendRead(d, meta)
}

func transitSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Unmounting Transit backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("error unmounting Transit backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted Transit backend %q", path)

	return nil
}

func transitSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if Transit backend exists at %q", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if Transit backend exists at %q", path)
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if mount.Type != "transit" {
		return false, nil
	}

	return ok, nil
}
