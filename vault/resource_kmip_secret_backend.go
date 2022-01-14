package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-provider-vault/util"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	kmipAPIFields = []string{
		"listen_addrs", "server_hostnames", "server_ips", "tls_ca_key_type", "tls_ca_key_bits",
		"tls_min_version", "default_tls_client_key_type",
		"default_tls_client_key_bits", "default_tls_client_ttl",
	}
)

func kmipSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: kmipSecretBackendCreate,
		Read:   kmipSecretBackendRead,
		Update: kmipSecretBackendUpdate,
		Delete: kmipSecretBackendDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where the generic secret will be written",
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend",
			},
			"listen_addrs": {
				Type:        schema.TypeSet,
				Optional:    true,
				Computed:    true,
				Description: "Address and port the KMIP server should listen on",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"server_hostnames": {
				Type:        schema.TypeSet,
				Optional:    true,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Hostnames to include in the server's TLS certificate as SAN DNS names. The first will be used as the common name (CN)",
			},
			"server_ips": {
				Type:        schema.TypeSet,
				Optional:    true,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "IPs to include in the server's TLS certificate as SAN IP addresses",
			},

			"tls_ca_key_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "CA key type, rsa or ec",
			},
			"tls_ca_key_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "CA key bits, valid values depend on key type",
			},
			"tls_min_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Minimum TLS version to accept",
			},
			"default_tls_client_key_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Client certificate key type, rsa or ec",
			},
			"default_tls_client_key_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Client certificate key bits, valid values depend on key type",
			},
			"default_tls_client_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Client certificate TTL in either an integer number of seconds (10)",
			},
		},
	}
}

func kmipSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Get("path").(string)
	description := d.Get("description").(string)
	defaultTLSClientTTL := d.Get("default_tls_client_ttl").(int)

	log.Printf("[DEBUG] Mounting KMIP backend at %q", path)
	err := client.Sys().Mount(path, &api.MountInput{
		Type:        "kmip",
		Description: description,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%d", defaultTLSClientTTL),
		},
	})
	if err != nil {
		return fmt.Errorf("error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted KMIP backend at %q", path)
	d.SetId(path)
	return kmipSecretBackendUpdate(d, meta)
}

func kmipSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()
	tune := api.MountConfigInput{}

	if d.HasChange("default_tls_client_ttl") || d.HasChange("description") {
		tune.DefaultLeaseTTL = fmt.Sprintf("%ds", d.Get("default_tls_client_ttl"))
		description := d.Get("description").(string)
		tune.Description = &description

		log.Printf("[DEBUG] Updating mount for %q", path)
		err := client.Sys().TuneMount(path, tune)
		if err != nil {
			return fmt.Errorf("error updating mount for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated mount for %q", path)
	}

	data := map[string]interface{}{}
	configPath := fmt.Sprintf("%s/config", path)
	log.Printf("[DEBUG] Updating %q", configPath)

	for _, k := range kmipAPIFields {
		if d.HasChange(k) {
			if v, ok := d.GetOk(k); ok {
				switch v.(type) {
				case *schema.Set:
					data[k] = util.TerraformSetToStringArray(v)
				default:
					data[k] = v
				}
			}
		}
	}
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("error updating KMIP config %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Updated %q", configPath)

	return kmipSecretBackendRead(d, meta)
}

func kmipSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Reading KMIP config at %s/config", path)
	resp, err := client.Logical().Read(path + "/config")
	if err != nil {
		return fmt.Errorf("error reading KMIP config at %q/config: %s", path, err)
	}
	if resp == nil {
		log.Printf("[WARN] KMIP config not found, removing from state")
		d.SetId("")
		return nil
	}
	for _, k := range kmipAPIFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on KMIP config: %s", k, err)
		}
	}
	return nil
}

func kmipSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()
	log.Printf("[DEBUG] Unmounting KMIP backend %q", path)

	err := client.Sys().Unmount(path)
	if err != nil && util.Is404(err) {
		log.Printf("[WARN] %q not found, removing from state", path)
		d.SetId("")
		return fmt.Errorf("error unmounting KMIP backend from %q: %s", path, err)
	} else if err != nil {
		return fmt.Errorf("error unmounting KMIP backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted KMIP backend %q", path)
	return nil
}
