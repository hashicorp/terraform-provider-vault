// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func pkiSecretBackendSignResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pkiSecretBackendSignCreate,
		DeleteContext: pkiSecretBackendSignDelete,
		UpdateContext: func(ctx context.Context, data *schema.ResourceData, i interface{}) diag.Diagnostics {
			return nil
		},
		ReadContext: provider.ReadContextWrapper(pkiSecretBackendCertRead),
		StateUpgraders: []schema.StateUpgrader{
			{
				Version: 0,
				Type:    pkiSecretSerialNumberResourceV0().CoreConfigSchema().ImpliedType(),
				Upgrade: pkiSecretSerialNumberUpgradeV0,
			},
		},
		SchemaVersion: 1,
		CustomizeDiff: pkiCertAutoRenewCustomizeDiff,

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role to create the certificate against.",
				ForceNew:    true,
			},
			consts.FieldCSR: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The CSR.",
				ForceNew:    true,
			},
			consts.FieldCommonName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "CN of intermediate to create.",
				ForceNew:    true,
			},
			consts.FieldAltNames: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of alternative names.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldOtherSans: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of other SANs.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldIPSans: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of alternative IPs.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldURISans: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of alternative URIs.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldTTL: {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    false,
				Description: "Time to live.",
			},
			consts.FieldFormat: {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The format of data.",
				ForceNew:     true,
				Default:      "pem",
				ValidateFunc: validation.StringInSlice([]string{"pem", "der", "pem_bundle"}, false),
			},
			consts.FieldExcludeCNFromSans: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Flag to exclude CN from SANs.",
				ForceNew:    true,
			},
			consts.FieldAutoRenew: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If enabled, a new certificate will be generated if the expiration is within min_seconds_remaining",
			},
			consts.FieldMinSecondsRemaining: {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     604800,
				Description: "Generate a new certificate when the expiration is within this number of seconds",
			},
			consts.FieldCertificate: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certicate.",
			},
			consts.FieldIssuingCA: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The issuing CA.",
			},
			consts.FieldCAChain: {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The CA chain.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldSerialNumber: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certificate's serial number, hex formatted.",
			},
			consts.FieldExpiration: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The certificate expiration as a Unix-style timestamp.",
			},
			consts.FieldRenewPending: {
				Type:     schema.TypeBool,
				Computed: true,
				Description: "Initially false, and then set to true during refresh once " +
					"the expiration is less than min_seconds_remaining in the future.",
			},
			consts.FieldIssuerRef: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the default issuer of this request.",
			},
			consts.FieldNotAfter: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Set the Not After field of the certificate with specified date value. " +
					"The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ. Supports the " +
					"Y10K end date for IEEE 802.1AR-2018 standard devices, 9999-12-31T23:59:59Z.",
			},
			consts.FieldCertMetadata: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "A base 64 encoded value or an empty string to associate with the certificate's " +
					"serial number. The role's no_store_metadata must be set to false, " +
					"otherwise an error is returned when specified.",
			},
			consts.FieldRemoveRootsFromChain: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				ForceNew:    true,
				Description: "If true, the returned ca_chain field will not include any self-signed CA certificates. Useful if end-users already have the root CA in their trust store.",
			},
		},
	}
}

func pkiSecretBackendSignCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	name := d.Get(consts.FieldName).(string)

	path := pkiSecretBackendIssuePath(backend, name)

	commonName := d.Get(consts.FieldCommonName).(string)

	signAPIFields := []string{
		consts.FieldCSR,
		consts.FieldCommonName,
		consts.FieldTTL,
		consts.FieldFormat,
		consts.FieldNotAfter,
	}

	signBooleanAPIFields := []string{
		consts.FieldExcludeCNFromSans,
		consts.FieldRemoveRootsFromChain,
	}

	signStringArrayAPIFields := []string{
		consts.FieldAltNames,
		consts.FieldOtherSans,
		consts.FieldIPSans,
		consts.FieldURISans,
	}

	data := map[string]interface{}{}
	for _, k := range signAPIFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	// add version specific multi-issuer fields
	if provider.IsAPISupported(meta, provider.VaultVersion111) {
		if issuerRef, ok := d.GetOk(consts.FieldIssuerRef); ok {
			data[consts.FieldIssuerRef] = issuerRef
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion117) {
		if certMetadata, ok := d.GetOk(consts.FieldCertMetadata); ok {
			data[consts.FieldCertMetadata] = certMetadata
		}
	}

	// add boolean fields
	for _, k := range signBooleanAPIFields {
		data[k] = d.Get(k)
	}

	// add comma separated string fields
	for _, k := range signStringArrayAPIFields {
		m := util.ToStringArray(d.Get(k).([]interface{}))
		if len(m) > 0 {
			data[k] = strings.Join(m, ",")
		}
	}

	log.Printf("[DEBUG] Creating certificate sign %s by %s on PKI secret backend %q", commonName, name,
		backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating certificate sign %s by %s for PKI secret backend %q: %s",
			commonName, name, backend, err)
	}
	log.Printf("[DEBUG] Created certificate sign %s by %s on PKI secret backend %q", commonName, name,
		backend)

	certFieldsMap := map[string]string{
		consts.FieldCertificate:  consts.FieldCertificate,
		consts.FieldIssuingCA:    consts.FieldIssuingCA,
		consts.FieldCAChain:      consts.FieldCAChain,
		consts.FieldSerialNumber: consts.FieldSerialNumber,
		consts.FieldExpiration:   consts.FieldExpiration,
	}

	for k, v := range certFieldsMap {
		if err := d.Set(k, resp.Data[v]); err != nil {
			return diag.FromErr(err)
		}
	}

	if err := pkiSecretBackendCertSynchronizeRenewPending(d); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(fmt.Sprintf("%s/%s/%s", backend, name, commonName))

	return pkiSecretBackendCertRead(ctx, d, meta)
}

func pkiSecretBackendSignDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendIssuePath(backend string, name string) string {
	return strings.Trim(backend, "/") + "/sign/" + strings.Trim(name, "/")
}
