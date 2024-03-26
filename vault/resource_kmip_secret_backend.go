// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

var kmipAPIFields = []string{
	"default_tls_client_key_bits",
	"default_tls_client_key_type",
	"default_tls_client_ttl",
	"listen_addrs",
	"server_hostnames",
	"server_ips",
	"tls_ca_key_bits",
	"tls_ca_key_type",
	"tls_min_version",
}

func kmipSecretBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		Create:        kmipSecretBackendCreate,
		Read:          provider.ReadWrapper(kmipSecretBackendRead),
		Update:        kmipSecretBackendUpdate,
		Delete:        kmipSecretBackendDelete,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where KMIP secret backend will be mounted",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
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
				Description: "Addresses the KMIP server should listen on (host:port)",
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
				Description: "Client certificate TTL in seconds",
			},
		},
	}, false)
}

func kmipSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := d.Get("path").(string)
	defaultTLSClientTTL := fmt.Sprintf("%ds", d.Get("default_tls_client_ttl").(int))

	log.Printf("[DEBUG] Mounting KMIP backend at %q", path)
	if err := client.Sys().Mount(path, &api.MountInput{
		Type:        consts.MountTypeKMIP,
		Description: d.Get("description").(string),
		Config: api.MountConfigInput{
			DefaultLeaseTTL: defaultTLSClientTTL,
		},
	}); err != nil {
		return fmt.Errorf("error mounting to %q, err=%w", path, err)
	}

	log.Printf("[DEBUG] Mounted KMIP backend at %q", path)
	d.SetId(path)

	return kmipSecretBackendUpdate(d, meta)
}

func kmipSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := d.Id()

	if !d.IsNewResource() && d.HasChange("path") {
		src := path
		dest := d.Get("path").(string)

		log.Printf("[DEBUG] Remount %s to %s in Vault", src, dest)

		err := client.Sys().Remount(src, dest)
		if err != nil {
			return fmt.Errorf("error remounting in Vault: %s", err)
		}

		// There is something similar in resource_mount.go, but in the call to TuneMount().
		var tries int
		for {
			if tries > 10 {
				return fmt.Errorf(
					"mount %q did did not become available after %d tries, interval=1s", dest, tries)
			}

			enabled, err := mountutil.CheckMountEnabled(client, dest)
			if err != nil {
				return err
			}
			if !enabled {
				tries++
				time.Sleep(1 * time.Second)
				continue
			}

			break
		}

		path = dest
		d.SetId(path)
	}

	log.Printf("[DEBUG] Updating mount %s in Vault", path)

	if d.HasChange("default_tls_client_ttl") || d.HasChange("description") {
		tune := api.MountConfigInput{}
		tune.DefaultLeaseTTL = fmt.Sprintf("%ds", d.Get("default_tls_client_ttl"))
		description := d.Get("description").(string)
		tune.Description = &description

		log.Printf("[DEBUG] Updating mount for %q", path)
		err := client.Sys().TuneMount(path, tune)
		if err != nil {
			return fmt.Errorf("error updating mount for %q, err=%w", path, err)
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
		return fmt.Errorf("error updating KMIP config %q, err=%w", configPath, err)
	}

	log.Printf("[DEBUG] Updated %q", configPath)

	return kmipSecretBackendRead(d, meta)
}

func kmipSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Reading KMIP config at %s/config", path)
	resp, err := client.Logical().Read(path + "/config")
	if err != nil {
		return fmt.Errorf("error reading KMIP config at %q/config: err=%w", path, err)
	}

	if resp == nil {
		log.Printf("[WARN] KMIP config not found, removing from state")
		d.SetId("")

		return nil
	}

	for _, k := range kmipAPIFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key %q on KMIP config, err=%w", k, err)
		}
	}

	return nil
}

func kmipSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := d.Id()
	log.Printf("[DEBUG] Unmounting KMIP backend %q", path)

	if err := client.Sys().Unmount(path); err != nil {
		if util.Is404(err) {
			log.Printf("[WARN] %q not found, removing from state", path)
			d.SetId("")

			return fmt.Errorf("error unmounting KMIP backend from %q, err=%w", path, err)
		}

		return fmt.Errorf("error unmounting KMIP backend from %q, err=%w", path, err)
	}

	log.Printf("[DEBUG] Unmounted KMIP backend %q", path)

	return nil
}
