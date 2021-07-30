package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
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
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "consul",
				Description: "Unique name of the Vault Consul mount to configure",
				StateFunc: func(s interface{}) string {
					return strings.Trim(s.(string), "/")
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
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
				Default:     "0",
				Description: "Default lease duration for secrets in seconds",
			},
			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "0",
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
			"ca_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "CA certificate to use when verifying Consul server certificate, must be x509 PEM encoded.",
				Sensitive:   false,
			},
			"client_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Client certificate used for Consul's TLS communication, must be x509 PEM encoded and if this is set you need to also set client_key.",
				Sensitive:   true,
			},
			"client_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Client key used for Consul's TLS communication, must be x509 PEM encoded and if this is set you need to also set client_cert.",
				Sensitive:   true,
			},
			"local": {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Default:     false,
				Description: "Specifies if the secret backend is local only",
			},
		},
	}
}

func consulSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	address := d.Get("address").(string)
	scheme := d.Get("scheme").(string)
	token := d.Get("token").(string)
	ca_cert := d.Get("ca_cert").(string)
	client_cert := d.Get("client_cert").(string)
	client_key := d.Get("client_key").(string)
	local := d.Get("local").(bool)

	configPath := consulSecretBackendConfigPath(path)

	info := &api.MountInput{
		Type:        "consul",
		Description: d.Get("description").(string),
		Local:       local,
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

	log.Printf("[DEBUG] Mounted Consul backend at %q", path)
	d.SetId(path)

	d.SetPartial("path")
	d.SetPartial("description")
	d.SetPartial("default_lease_ttl_seconds")
	d.SetPartial("max_lease_ttl_seconds")

	log.Printf("[DEBUG] Writing Consul configuration to %q", configPath)
	data := map[string]interface{}{
		"address":     address,
		"token":       token,
		"scheme":      scheme,
		"ca_cert":     ca_cert,
		"client_cert": client_cert,
		"client_key":  client_key,
	}
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("Error writing Consul configuration for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Consul configuration to %q", configPath)
	d.SetPartial("address")
	d.SetPartial("token")
	d.SetPartial("scheme")
	d.SetPartial("ca_cert")
	d.SetPartial("client_cert")
	d.SetPartial("client_key")
	d.Partial(false)

	return nil
}

func consulSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	configPath := consulSecretBackendConfigPath(path)

	log.Printf("[DEBUG] Reading Consul backend mount %q from Vault", path)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("Error reading mount %q: %s", path, err)
	}

	// path can have a trailing slash, but doesn't need to have one
	// this standardises on having a trailing slash, which is how the
	// API always responds.
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing from state.", path)
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
	d.Set("scheme", secret.Data["scheme"].(string))

	return nil
}

func consulSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
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
		if err := client.Sys().TuneMount(path, config); err != nil {
			return fmt.Errorf("Error updating mount TTLs for %q: %s", path, err)
		}

		d.SetPartial("default_lease_ttl_seconds")
		d.SetPartial("max_lease_ttl_seconds")
	}
	if d.HasChange("address") || d.HasChange("token") || d.HasChange("scheme") ||
		d.HasChange("ca_cert") || d.HasChange("client_cert") || d.HasChange("client_key") {
		log.Printf("[DEBUG] Updating Consul configuration at %q", configPath)
		data := map[string]interface{}{
			"address":     d.Get("address").(string),
			"token":       d.Get("token").(string),
			"scheme":      d.Get("scheme").(string),
			"ca_cert":     d.Get("ca_cert").(string),
			"client_cert": d.Get("client_cert").(string),
			"client_key":  d.Get("client_key").(string),
		}
		if _, err := client.Logical().Write(configPath, data); err != nil {
			return fmt.Errorf("Error configuring Consul configuration for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated Consul configuration at %q", configPath)
		d.SetPartial("address")
		d.SetPartial("token")
		d.SetPartial("scheme")
		d.SetPartial("ca_cert")
		d.SetPartial("client_cert")
		d.SetPartial("client_key")
	}
	d.Partial(false)
	return consulSecretBackendRead(d, meta)
}

func consulSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Unmounting Consul backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("Error unmounting Consul backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted Consul backend %q", path)
	return nil
}

func consulSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Checking if Consul backend exists at %q", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("Error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if Consul backend exists at %q", path)
	_, ok := mounts[strings.Trim(path, "/")+"/"]
	return ok, nil
}

func consulSecretBackendConfigPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/access"
}
