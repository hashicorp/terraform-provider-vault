package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-provider-vault/util"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func nomadSecretAccessBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"backend": {
			Type:        schema.TypeString,
			Default:     "nomad",
			ForceNew:    true,
			Optional:    true,
			Description: "The mount path for the Nomad backend.",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"address": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Specifies the address of the Nomad instance, provided as "protocol://host:port" like "http://127.0.0.1:4646".`,
		},
		"ca_cert": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `CA certificate to use when verifying Nomad server certificate, must be x509 PEM encoded.`,
		},
		"client_cert": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: `Client certificate used for Nomad's TLS communication, must be x509 PEM encoded and if this is set you need to also set client_key.`,
		},
		"client_key": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: `Client key used for Nomad's TLS communication, must be x509 PEM encoded and if this is set you need to also set client_cert.`,
		},
		"default_lease_ttl_seconds": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `Default lease duration for secrets in seconds.`,
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Human-friendly description of the mount for the backend.`,
		},
		"local": {
			Type:        schema.TypeBool,
			Required:    false,
			Optional:    true,
			Description: `Mark the secrets engine as local-only. Local engines are not replicated or removed by replication. Tolerance duration to use when checking the last rotation time.`,
		},
		"max_lease_ttl_seconds": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
		"max_token_name_length": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `Specifies the maximum length to use for the name of the Nomad token generated with Generate Credential. If omitted, 0 is used and ignored, defaulting to the max value allowed by the Nomad version.`,
		},
		"max_ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
		"token": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: `Specifies the Nomad Management token to use.`,
		},
		"ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
	}
	return &schema.Resource{
		Create: createNomadAccessConfigResource,
		Update: updateNomadAccessConfigResource,
		Read:   readNomadAccessConfigResource,
		Delete: deleteNomadAccessConfigResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func createNomadAccessConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	backend := d.Get("backend").(string)
	description := d.Get("description").(string)
	defaultTTL := d.Get("default_lease_ttl_seconds").(int)
	local := d.Get("local").(bool)
	maxTTL := d.Get("max_lease_ttl_seconds").(int)

	log.Printf("[DEBUG] Mounting Nomad backend at %q", backend)
	err := client.Sys().Mount(backend, &api.MountInput{
		Type:        "nomad",
		Description: description,
		Local:       local,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
			MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
		},
	})
	if err != nil {
		return fmt.Errorf("error mounting to %q: %s", backend, err)
	}

	log.Printf("[DEBUG] Mounted Nomad backend at %q", backend)
	d.SetId(backend)

	data := map[string]interface{}{}
	if v, ok := d.GetOkExists("address"); ok {
		data["address"] = v
	}

	if v, ok := d.GetOkExists("ca_cert"); ok {
		data["ca_cert"] = v
	}

	if v, ok := d.GetOkExists("client_cert"); ok {
		data["client_cert"] = v
	}

	if v, ok := d.GetOkExists("client_key"); ok {
		data["client_key"] = v
	}

	if v, ok := d.GetOkExists("max_token_name_length"); ok {
		data["max_token_name_length"] = v
	}

	if v, ok := d.GetOkExists("token"); ok {
		data["token"] = v
	}

	configPath := fmt.Sprintf("%s/config/access", backend)
	log.Printf("[DEBUG] Writing %q", configPath)
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("error writing %q: %s", configPath, err)
	}

	dataLease := map[string]interface{}{}
	if v, ok := d.GetOkExists("max_ttl"); ok {
		dataLease["max_ttl"] = v
	}

	if v, ok := d.GetOkExists("ttl"); ok {
		dataLease["ttl"] = v
	}

	configLeasePath := fmt.Sprintf("%s/config/lease", backend)
	log.Printf("[DEBUG] Writing %q", configLeasePath)
	if _, err := client.Logical().Write(configLeasePath, dataLease); err != nil {
		return fmt.Errorf("error writing %q: %s", configLeasePath, err)
	}

	log.Printf("[DEBUG] Wrote %q", configLeasePath)
	return readNomadAccessConfigResource(d, meta)
}

func readNomadAccessConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Reading %q", path)

	mountResp, err := client.Sys().MountConfig(path)
	if err != nil && util.Is404(err) {
		log.Printf("[WARN] %q not found, removing from state", path)
		d.SetId("")
		return nil
	} else if err != nil {
		return fmt.Errorf("error reading %q: %s", path, err)
	}

	d.Set("backend", d.Id())
	d.Set("default_lease_ttl_seconds", mountResp.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mountResp.MaxLeaseTTL)

	configPath := fmt.Sprintf("%s/config/access", d.Id())
	log.Printf("[DEBUG] Reading %q", configPath)

	resp, err := client.Logical().Read(configPath)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Read %q", configPath)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", configPath)
		d.SetId("")
		return nil
	}

	if val, ok := resp.Data["address"]; ok {
		if err := d.Set("address", val); err != nil {
			return fmt.Errorf("error setting state key 'address': %s", err)
		}
	}

	if val, ok := resp.Data["ca_cert"]; ok {
		if err := d.Set("ca_cert", val); err != nil {
			return fmt.Errorf("error setting state key 'ca_cert': %s", err)
		}
	}

	if val, ok := resp.Data["client_cert"]; ok {
		if err := d.Set("client_cert", val); err != nil {
			return fmt.Errorf("error setting state key 'client_cert': %s", err)
		}
	}

	if val, ok := resp.Data["client_key"]; ok {
		if err := d.Set("client_key", val); err != nil {
			return fmt.Errorf("error setting state key 'client_key': %s", err)
		}
	}

	if val, ok := resp.Data["max_token_name_length"]; ok {
		if err := d.Set("max_token_name_length", val); err != nil {
			return fmt.Errorf("error setting state key 'max_token_name_length': %s", err)
		}
	}

	configLeasePath := fmt.Sprintf("%s/config/lease", d.Id())
	log.Printf("[DEBUG] Reading %q", configLeasePath)

	resp, err = client.Logical().Read(configLeasePath)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", configLeasePath, err)
	}
	log.Printf("[DEBUG] Read %q", configLeasePath)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", configLeasePath)
		d.SetId("")
		return nil
	}

	if val, ok := resp.Data["max_ttl"]; ok {
		if err := d.Set("max_ttl", val); err != nil {
			return fmt.Errorf("error setting state key 'max_ttl': %s", err)
		}
	}

	if val, ok := resp.Data["ttl"]; ok {
		if err := d.Set("ttl", val); err != nil {
			return fmt.Errorf("error setting state key 'ttl': %s", err)
		}
	}

	return nil
}

func updateNomadAccessConfigResource(d *schema.ResourceData, meta interface{}) error {
	backend := d.Id()

	client := meta.(*api.Client)
	tune := api.MountConfigInput{}
	data := map[string]interface{}{}

	if d.HasChange("default_lease_ttl_seconds") || d.HasChange("max_lease_ttl_seconds") {
		tune.DefaultLeaseTTL = fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds"))
		tune.MaxLeaseTTL = fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds"))

		log.Printf("[DEBUG] Updating mount lease TTLs for %q", backend)
		err := client.Sys().TuneMount(backend, tune)
		if err != nil {
			return fmt.Errorf("error updating mount TTLs for %q: %s", backend, err)
		}
		log.Printf("[DEBUG] Updated lease TTLs for %q", backend)
	}

	configPath := fmt.Sprintf("%s/config/access", backend)
	log.Printf("[DEBUG] Updating %q", configPath)

	if raw, ok := d.GetOk("address"); ok {
		data["address"] = raw
	}

	if raw, ok := d.GetOk("ca_cert"); ok {
		data["ca_cert"] = raw
	}

	if raw, ok := d.GetOk("client_cert"); ok {
		data["client_cert"] = raw
	}

	if raw, ok := d.GetOk("client_key"); ok {
		data["client_key"] = raw
	}

	if raw, ok := d.GetOk("max_token_name_length"); ok {
		data["max_token_name_length"] = raw
	}

	if raw, ok := d.GetOk("token"); ok {
		data["token"] = raw
	}

	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("error updating access config %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Updated %q", configPath)

	configLeasePath := fmt.Sprintf("%s/config/lease", backend)
	log.Printf("[DEBUG] Updating %q", configLeasePath)

	dataLease := map[string]interface{}{}

	if raw, ok := d.GetOk("max_ttl"); ok {
		dataLease["max_ttl"] = raw
	}

	if raw, ok := d.GetOk("ttl"); ok {
		dataLease["ttl"] = raw
	}

	if _, err := client.Logical().Write(configLeasePath, dataLease); err != nil {
		return fmt.Errorf("error updating lease config %q: %s", configLeasePath, err)
	}

	log.Printf("[DEBUG] Updated %q", configLeasePath)
	return readNomadAccessConfigResource(d, meta)
}

func deleteNomadAccessConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Unmounting Nomad backend %q", vaultPath)

	err := client.Sys().Unmount(vaultPath)
	if err != nil && util.Is404(err) {
		log.Printf("[WARN] %q not found, removing from state", vaultPath)
		d.SetId("")
		return fmt.Errorf("error unmounting Nomad backend from %q: %s", vaultPath, err)
	} else if err != nil {
		return fmt.Errorf("error unmounting Nomad backend from %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Unmounted Nomad backend %q", vaultPath)
	return nil
}
