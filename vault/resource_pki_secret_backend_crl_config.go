package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendCrlConfigResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendCrlConfigCreate,
		Read:   ReadWrapper(pkiSecretBackendCrlConfigRead),
		Update: pkiSecretBackendCrlConfigUpdate,
		Delete: pkiSecretBackendCrlConfigDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path of the PKI secret backend the resource belongs to.",
				ForceNew:    true,
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"expiry": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the time until expiration.",
			},
			"disable": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Disables or enables CRL building",
			},
			"ocsp_disable": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Disables or enables the OCSP responder in Vault.",
			},
			"ocsp_expiry": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The amount of time an OCSP response can be cached for, (controls the NextUpdate field), useful for OCSP stapling refresh durations.",
				Default:     "12h",
			},
			"auto_rebuild": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enables or disables periodic rebuilding of the CRL upon expiry.",
			},
			"auto_rebuild_grace_period": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Grace period before CRL expiry to attempt rebuild of CRL.",
				Default:     "12h",
			},
			"enable_delta": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enables or disables building of delta CRLs with up-to-date revocation information, augmenting the last complete CRL.",
			},
			"delta_rebuild_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Interval to check for new revocations on, to regenerate the delta CRL.",
				Default:     "15m",
			},
		},
	}
}

func pkiSecretBackendCrlConfigCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	path := pkiSecretBackendCrlConfigPath(backend)

	data := make(map[string]interface{})
	if expiry, ok := d.GetOk("expiry"); ok {
		data["expiry"] = expiry
	}
	if disable, ok := d.GetOk("disable"); ok {
		data["disable"] = disable
	}
	if ocsp_disable, ok := d.GetOk("ocsp_disable"); ok {
		data["ocsp_disable"] = ocsp_disable
	}
	if ocsp_expiry, ok := d.GetOk("ocsp_expiry"); ok {
		data["ocsp_expiry"] = ocsp_expiry
	}
	if auto_rebuild, ok := d.GetOk("auto_rebuild"); ok {
		data["auto_rebuild"] = auto_rebuild
	}
	if auto_rebuild_grace_period, ok := d.GetOk("auto_rebuild_grace_period"); ok {
		data["auto_rebuild_grace_period"] = auto_rebuild_grace_period
	}
	if enable_delta, ok := d.GetOk("enable_delta"); ok {
		data["enable_delta"] = enable_delta
	}
	if delta_rebuild_interval, ok := d.GetOk("delta_rebuild_interval"); ok {
		data["delta_rebuild_interval"] = delta_rebuild_interval
	}

	log.Printf("[DEBUG] Creating CRL config on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating CRL config PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created CRL config on PKI secret backend %q", backend)

	d.SetId(path)
	return pkiSecretBackendCrlConfigRead(d, meta)
}

func pkiSecretBackendCrlConfigRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	backend := pkiSecretBackendCrlConfigPath(path)

	log.Printf("[DEBUG] Reading CRL config from PKI secret backend %q", backend)
	config, err := client.Logical().Read(path)
	if err != nil {
		log.Printf("[WARN] Removing path %q its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid path ID %q: %s", path, err)
	}

	if config == nil {
		d.SetId("")
		return nil
	}

	d.Set("expiry", config.Data["expiry"])
	d.Set("disable", config.Data["disable"])
	d.Set("ocsp_disable", config.Data["ocsp_disable"])
	d.Set("ocsp_expiry", config.Data["ocsp_expiry"])
	d.Set("auto_rebuild", config.Data["auto_rebuild"])
	d.Set("auto_rebuild_grace_period", config.Data["auto_rebuild_grace_period"])
	d.Set("enable_delta", config.Data["enable_delta"])
	d.Set("delta_rebuild_interval", config.Data["delta_rebuild_interval"])

	return nil
}

func pkiSecretBackendCrlConfigUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	backend := pkiSecretBackendCrlConfigPath(path)

	data := make(map[string]interface{})
	if expiry, ok := d.GetOk("expiry"); ok {
		data["expiry"] = expiry
	}
	if disable, ok := d.GetOk("disable"); ok {
		data["disable"] = disable
	}
	if ocsp_disable, ok := d.GetOk("ocsp_disable"); ok {
		data["ocsp_disable"] = ocsp_disable
	}
	if ocsp_expiry, ok := d.GetOk("ocsp_expiry"); ok {
		data["ocsp_expiry"] = ocsp_expiry
	}
	if auto_rebuild, ok := d.GetOk("auto_rebuild"); ok {
		data["auto_rebuild"] = auto_rebuild
	}
	if auto_rebuild_grace_period, ok := d.GetOk("auto_rebuild_grace_period"); ok {
		data["auto_rebuild_grace_period"] = auto_rebuild_grace_period
	}
	if enable_delta, ok := d.GetOk("enable_delta"); ok {
		data["enable_delta"] = enable_delta
	}
	if delta_rebuild_interval, ok := d.GetOk("delta_rebuild_interval"); ok {
		data["delta_rebuild_interval"] = delta_rebuild_interval
	}

	log.Printf("[DEBUG] Updating CRL config on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating CRL config for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Updated CRL config on PKI secret backend %q", backend)

	return pkiSecretBackendCrlConfigRead(d, meta)
}

func pkiSecretBackendCrlConfigDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendCrlConfigPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/crl"
}
