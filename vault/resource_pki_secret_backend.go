package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
	"strings"
)

func pkiSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		DeprecationMessage: `This resource duplicates "vault_mount" and will be removed in the next major release.`,
		Create:             pkiSecretBackendCreate,
		Read:               pkiSecretBackendRead,
		Update:             pkiSecretBackendUpdate,
		Delete:             pkiSecretBackendDelete,
		Exists:             pkiSecretBackendExists,
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

func pkiSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	description := d.Get("description").(string)
	defaultTTL := d.Get("default_lease_ttl_seconds").(int)
	maxTTL := d.Get("max_lease_ttl_seconds").(int)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting PKI backend at %q", path)
	err := client.Sys().Mount(path, &api.MountInput{
		Type:        "pki",
		Description: description,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
			MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
		},
	})
	if err != nil {
		return fmt.Errorf("error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted PKI backend at %q", path)
	d.SetId(path)

	d.Partial(false)

	return pkiSecretBackendRead(d, meta)
}

func pkiSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Reading PKI backend mount %q from Vault", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading mount %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read PKI backend mount %q from Vault", path)

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

func pkiSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
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
	}
	d.Partial(false)

	return pkiSecretBackendRead(d, meta)
}

func pkiSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Unmounting PKI backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("error unmounting PKI backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted PKI backend %q", path)

	return nil
}

func pkiSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if PKI backend exists at %q", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if PKI backend exists at %q", path)
	_, ok := mounts[strings.Trim(path, "/")+"/"]

	return ok, nil
}
