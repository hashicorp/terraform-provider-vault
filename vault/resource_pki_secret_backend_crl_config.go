// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	crlConfigPathBase = "/config/crl"
)

func pkiSecretBackendCrlConfigResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pkiSecretBackendCrlConfigCreate,
		ReadContext:   provider.ReadContextWrapper(pkiSecretBackendCrlConfigRead),
		UpdateContext: pkiSecretBackendCrlConfigUpdate,
		DeleteContext: pkiSecretBackendCrlConfigDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
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
			consts.FieldMaxCrlEntries: {
				Type:     schema.TypeInt,
				Optional: true,
				Description: "The maximum number of entries a CRL can contain. This option exists to " +
					"prevent accidental runaway issuance/revocation from overloading Vault. If set " +
					"to -1, the limit is disabled.",
				Computed: true,
			},
		},
	}
}

func pkiSecretBackendCrlConfigCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.Errorf("failed getting client: %v", e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := pkiSecretBackendCrlConfigPath(backend)
	fields := buildConfigCRLFields(meta)

	data := util.GetAPIRequestDataWithSliceOkExists(d, fields)
	log.Printf("[DEBUG] Creating CRL config on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating CRL config PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created CRL config on PKI secret backend %q", backend)

	d.SetId(path)
	return pkiSecretBackendCrlConfigRead(ctx, d, meta)
}

func pkiSecretBackendCrlConfigRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.Errorf("failed getting client: %v", e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Reading PKI CRL config from path %q", path)
	config, err := client.Logical().Read(path)
	if err != nil {
		log.Printf("[WARN] Removing path %q its ID is invalid, err=%s", path, err)
		d.SetId("")
		return diag.Errorf("invalid path ID %q: %v", path, err)
	}

	if config == nil {
		d.SetId("")
		return diag.Errorf("received nil response from %q", path)
	}

	if _, ok := d.GetOk(consts.FieldBackend); !ok {
		// ensure that the backend is set on import
		if err := d.Set(consts.FieldBackend, strings.TrimRight(path, crlConfigPathBase)); err != nil {
			return diag.Errorf("failed setting field %s: %v", consts.FieldBackend, err)
		}
	}

	for _, field := range buildConfigCRLFields(meta) {
		if err := d.Set(field, config.Data[field]); err != nil {
			return diag.Errorf("failed setting field %s: %v", field, err)
		}
	}

	return nil
}

func pkiSecretBackendCrlConfigUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.Errorf("failed getting client: %v", e)
	}

	path := d.Id()
	fields := buildConfigCRLFields(meta)

	data := util.GetAPIRequestDataWithSliceOkExists(d, fields)
	log.Printf("[DEBUG] Updating CRL config on PKI secret path %q", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error updating CRL config for PKI secret path %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated CRL config on PKI secret path %q", path)

	return pkiSecretBackendCrlConfigRead(ctx, d, meta)
}

func pkiSecretBackendCrlConfigDelete(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendCrlConfigPath(backend string) string {
	return strings.Trim(backend, "/") + crlConfigPathBase
}

func buildConfigCRLFields(meta interface{}) []string {
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

	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		fields = append(fields, []string{
			consts.FieldMaxCrlEntries,
		}...)
	}

	return fields
}
