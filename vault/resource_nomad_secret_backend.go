package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func nomadSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: nomadSecretBackendCreate,
		Read:   nomadSecretBackendRead,
		Update: nomadSecretBackendUpdate,
		Delete: nomadSecretBackendDelete,
		Exists: nomadSecretBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "nomad",
				ForceNew:    true,
				Description: "Unique name of the Vault Nomad mount to configure",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
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
				Description: "Specifies the address of the Nomad instance, provided as \"host:port\" like \"127.0.0.1:4646\".", //TODO: is 4646 the right port?
			},
			"token": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the Nomad ACL token to use. This must be a management type token.",
				Sensitive:   true,
			},
		},
	}
}

func nomadSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	address := d.Get("address").(string)
	token := d.Get("token").(string)

	configPath := nomadSecretBackendConfigPath(path)

	info := &api.MountInput{
		Type:        "nomad",
		Description: d.Get("description").(string),
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		},
	}

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Consul backend at %q", path)

	if err := client.Sys().Mount(path, info); err != nil {
		return fmt.Errorf("Error mounting to %q: %s", path, err)
	}

	log.Printf("[DEBUG] Mounted Nomad backend at %q", path)
	d.SetId(path)

	d.SetPartial("path")
	d.SetPartial("description")
	d.SetPartial("default_lease_ttl_seconds")
	d.SetPartial("max_lease_ttl_seconds")

	log.Printf("[DEBUG] Writing connection credentials to %q", configPath)
	data := map[string]interface{}{
		"address": address,
		"token":   token,
	}
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("Error writing Nomad configuration for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Nomad configuration to %q", configPath)
	d.SetPartial("address")
	d.SetPartial("token")
	d.Partial(false)
	return nil
	// return nomadSecretBackendRead(d, meta) //TODO: Why is this set in rabbit but not consul?
}

func nomadSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	configPath := nomadSecretBackendConfigPath(path)

	log.Printf("[DEBUG] Reading Nomad secret backend mount %q from Vault", path)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading mount %q: %s", path, err)
	}

	// path can have a trailing slash, but doesn't need to have one
	// this standardises on having a trailing slash, which is how the
	// API always responds.
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

	log.Printf("[DEBUG] Reading %s from Vault", configPath)
	secret, err := client.Logical().Read(configPath)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	log.Printf("[DEBUG] secret: %#v", secret)

	// token, sadly, we can't read out
	// the API doesn't support it
	// So... if it drifts, it drift.
	d.Set("address", secret.Data["address"].(string))

	return nil
}

func nomadSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	configPath := consulSecretBackendConfigPath(path)

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
	if d.HasChange("address") || d.HasChange("token") {
		log.Printf("[DEBUG] Updating Nomad configuration at %q", configPath)
		data := map[string]interface{}{
			"address": d.Get("address").(string),
			"token":   d.Get("token").(string),
		}
		if _, err := client.Logical().Write(configPath, data); err != nil {
			return fmt.Errorf("Error configuring Nomad configuration for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated Nomad configuration at %q", configPath)
		d.SetPartial("address")
		d.SetPartial("token")
	}
	d.Partial(false)
	return nomadSecretBackendRead(d, meta)
}

func nomadSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Unmounting Nomad backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("error unmounting Nomad backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted Nomad backend %q", path)
	return nil
}

func nomadSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if Nomad backend exists at %q", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if Nomad backend exists at %q", path)
	_, ok := mounts[strings.Trim(path, "/")+"/"]
	return ok, nil
}

func nomadSecretBackendConfigPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/access"
}
