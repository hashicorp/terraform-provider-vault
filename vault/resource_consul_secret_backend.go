package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func consulSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: consulSecretBackendCreate,
		Read:   consulSecretBackendRead,
		Update: consulSecretBackendUpdate,
		Delete: consulSecretBackendDelete,
		Exists: consulSecretBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "consul",
				Description: "Unique name of the Vault Consul mount to configure",
				StateFunc: func(s interface{}) string {
					return strings.Trim(s.(string), "/")
				},
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Default lease duration for secrets in seconds",
			},
			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Maximum possible lease duration for secrets in seconds",
			},
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the address of the Consul instance, provided as \"host:port\" like \"127.0.0.1:8500\".",
			},
			"scheme": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "http",
				Description: "Specifies the URL scheme to use. Defaults to \"http\".",
			},
			"token": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the Consul ACL token to use. This must be a management type token.",
				Sensitive:   true,
			},
		},
	}
}

func consulSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	address := d.Get("address").(string)
	scheme := d.Get("scheme").(string)
	token := d.Get("token").(string)

	path := consulSecretBackendPath(backend)

	info := &api.MountInput{
		Type:        "consul",
		Description: d.Get("description").(string),
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		},
	}

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Consul backend at %q", backend)

	if err := client.Sys().Mount(backend, info); err != nil {
		return fmt.Errorf("Error mounting to %q: %s", backend, err)
	}

	log.Printf("[DEBUG] Mounted Consul backend at %q", backend)
	d.SetId(path)

	d.SetPartial("backend")
	d.SetPartial("description")
	d.SetPartial("default_lease_ttl_seconds")
	d.SetPartial("max_lease_ttl_seconds")

	log.Printf("[DEBUG] Writing Consul configuration to %q", path)
	data := map[string]interface{}{
		"address": address,
		"token":   token,
		"scheme":  scheme,
	}
	if _, err := client.Logical().Write(path, data); err != nil {
		return fmt.Errorf("Error writing Consul configuration for %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Wrote Consul configuration to %q", path)
	d.SetPartial("address")
	d.SetPartial("token")
	d.SetPartial("scheme")
	d.Partial(false)

	return nil
}

func consulSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	backend := d.Get("backend").(string)

	log.Printf("[DEBUG] Reading Consul backend mount %q from Vault", backend)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("Error reading mount %q: %s", backend, err)
	}

	// backend can have a trailing slash, but doesn't need to have one
	// this standardises on having a trailing slash, which is how the
	// API always responds.
	mount, ok := mounts[strings.Trim(backend, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing from state.", backend)
		d.SetId("")
		return nil
	}

	d.Set("backend", backend)
	d.Set("description", mount.Description)
	d.Set("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL)

	log.Printf("[DEBUG] Reading %s from Vault", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	log.Printf("[DEBUG] secret: %#v", secret)

	// token, sadly, we can't read out
	// the API doesn't support it
	// So... if it drifts, it drift.
	d.Set("address", secret.Data["address"].(string))
	d.Set("scheme", secret.Data["scheme"].(string))

	return nil
}

func consulSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	backend := d.Get("backend").(string)

	d.Partial(true)

	if d.HasChange("default_lease_ttl_seconds") || d.HasChange("max_lease_ttl_seconds") {
		config := api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		}

		log.Printf("[DEBUG] Updating lease TTLs for %q", backend)
		if err := client.Sys().TuneMount(backend, config); err != nil {
			return fmt.Errorf("Error updating mount TTLs for %q: %s", backend, err)
		}

		d.SetPartial("default_lease_ttl_seconds")
		d.SetPartial("max_lease_ttl_seconds")
	}
	if d.HasChange("address") || d.HasChange("token") || d.HasChange("scheme") {
		log.Printf("[DEBUG] Updating Consul configuration at %q", path)
		data := map[string]interface{}{
			"address": d.Get("address").(string),
			"token":   d.Get("token").(string),
			"scheme":  d.Get("scheme").(string),
		}
		if _, err := client.Logical().Write(path, data); err != nil {
			return fmt.Errorf("Error configuring Consul configuration for %q: %s", backend, err)
		}
		log.Printf("[DEBUG] Updated Consul configuration at %q", path)
		d.SetPartial("address")
		d.SetPartial("token")
		d.SetPartial("scheme")
	}
	d.Partial(false)
	return consulSecretBackendRead(d, meta)
}

func consulSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)

	log.Printf("[DEBUG] Unmounting Consul backend %q", backend)
	err := client.Sys().Unmount(backend)
	if err != nil {
		return fmt.Errorf("Error unmounting Consul backend from %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Unmounted Consul backend %q", backend)
	return nil
}

func consulSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)

	log.Printf("[DEBUG] Checking if Consul backend exists at %q", backend)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("Error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if Consul backend exists at %q", backend)
	_, ok := mounts[strings.Trim(backend, "/")+"/"]
	return ok, nil
}

func consulSecretBackendPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/access"
}
