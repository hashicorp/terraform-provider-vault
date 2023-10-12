// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	crlConfigPathBase = "/config/crl"
)

func pkiSecretBackendCrlConfigResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendCrlConfigCreate,
		Read:   provider.ReadWrapper(pkiSecretBackendCrlConfigRead),
		Update: pkiSecretBackendCrlConfigUpdate,
		Delete: pkiSecretBackendCrlConfigDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

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
				Default:     false,
				Optional:    true,
				Description: "Disables or enables CRL building",
			},
			"ocsp_disable": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "Disables or enables the OCSP responder in Vault.",
			},
			"ocsp_expiry": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The amount of time an OCSP response can be cached for, " +
					"useful for OCSP stapling refresh durations.",
				Computed: true,
			},
			"auto_rebuild": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "Enables or disables periodic rebuilding of the CRL upon expiry.",
			},
			"auto_rebuild_grace_period": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Grace period before CRL expiry to attempt rebuild of CRL.",
				Computed:    true,
			},
			"enable_delta": {
				Type:     schema.TypeBool,
				Default:  false,
				Optional: true,
				Description: "Enables or disables building of delta CRLs with up-to-date revocation " +
					"information, augmenting the last complete CRL.",
			},
			"delta_rebuild_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Interval to check for new revocations on, to regenerate the delta CRL.",
				Computed:    true,
			},
			"cross_cluster_revocation": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable cross-cluster revocation request queues.",
				Computed:    true,
			},
			"unified_crl": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enables unified CRL and OCSP building.",
				Computed:    true,
			},
			"unified_crl_on_existing_paths": {
				Type:     schema.TypeBool,
				Optional: true,
				Description: "Enables serving the unified CRL and OCSP on the existing, previously " +
					"cluster-local paths.",
				Computed: true,
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

	fields := []string{
		"expiry",
		"disable",
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		fields = append(fields, []string{
			"ocsp_disable",
			"ocsp_expiry",
			"auto_rebuild",
			"auto_rebuild_grace_period",
			"enable_delta",
			"delta_rebuild_interval",
		}...)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion113) {
		fields = append(fields, []string{
			"cross_cluster_revocation",
			"unified_crl",
			"unified_crl_on_existing_paths",
		}...)
	}

	data := util.GetAPIRequestDataWithSliceOk(d, fields)
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
	log.Printf("[DEBUG] Reading PKI CRL config from path %q", path)
	config, err := client.Logical().Read(path)
	if err != nil {
		log.Printf("[WARN] Removing path %q its ID is invalid, err=%s", path, err)
		d.SetId("")
		return fmt.Errorf("invalid path ID %q: %w", path, err)
	}

	if config == nil {
		d.SetId("")
		return nil
	}

	if _, ok := d.GetOk("backend"); !ok {
		// ensure that the backend is set on import
		if err := d.Set("backend", strings.TrimRight(path, crlConfigPathBase)); err != nil {
			return err
		}
	}

	if err := util.SetResourceData(d, config.Data); err != nil {
		return err
	}

	return nil
}

func pkiSecretBackendCrlConfigUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	fields := []string{
		"expiry",
		"disable",
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		fields = append(fields, []string{
			"ocsp_disable",
			"ocsp_expiry",
			"auto_rebuild",
			"auto_rebuild_grace_period",
			"enable_delta",
			"delta_rebuild_interval",
		}...)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion113) {
		fields = append(fields, []string{
			"cross_cluster_revocation",
			"unified_crl",
			"unified_crl_on_existing_paths",
		}...)
	}

	data := util.GetAPIRequestDataWithSliceOk(d, fields)
	log.Printf("[DEBUG] Updating CRL config on PKI secret path %q", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating CRL config for PKI secret path %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated CRL config on PKI secret path %q", path)

	return pkiSecretBackendCrlConfigRead(d, meta)
}

func pkiSecretBackendCrlConfigDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendCrlConfigPath(backend string) string {
	return strings.Trim(backend, "/") + crlConfigPathBase
}
