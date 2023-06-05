// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/pem"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func pkiSecretBackendRootSignIntermediateResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pkiSecretBackendRootSignIntermediateCreate,
		ReadContext:   provider.ReadContextWrapper(pkiSecretBackendRootSignIntermediateRead),
		UpdateContext: pkiSecretBackendRootSignIntermediateUpdate,
		DeleteContext: pkiSecretBackendCertDelete,
		StateUpgraders: []schema.StateUpgrader{
			{
				Version: 0,
				Type:    pkiSecretRootSignIntermediateRV0().CoreConfigSchema().ImpliedType(),
				Upgrade: pkiSecretRootSignIntermediateRUpgradeV0,
			},
			{
				Version: 1,
				Type:    pkiSecretSerialNumberResourceV0().CoreConfigSchema().ImpliedType(),
				Upgrade: pkiSecretSerialNumberUpgradeV0,
			},
		},
		SchemaVersion: 2,
		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
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
			consts.FieldOtherSans: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of other SANs.",
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
			consts.FieldMaxPathLength: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The maximum path length to encode in the generated certificate.",
				ForceNew:    true,
				Default:     -1,
			},
			consts.FieldExcludeCNFromSans: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Flag to exclude CN from SANs.",
				ForceNew:    true,
			},
			consts.FieldUseCSRValues: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Preserve CSR values.",
				ForceNew:    true,
				Default:     false,
			},
			consts.FieldPermittedDNSDomains: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of domains for which certificates are allowed to be issued.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldOu: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The organization unit.",
				ForceNew:    true,
			},
			consts.FieldOrganization: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The organization.",
				ForceNew:    true,
			},
			consts.FieldCountry: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The country.",
				ForceNew:    true,
			},
			consts.FieldLocality: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The locality.",
				ForceNew:    true,
			},
			consts.FieldProvince: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The province.",
				ForceNew:    true,
			},
			consts.FieldStreetAddress: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The street address.",
				ForceNew:    true,
			},
			consts.FieldPostalCode: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The postal code.",
				ForceNew:    true,
			},
			consts.FieldCertificate: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The signed intermediate CA certificate.",
			},
			consts.FieldIssuingCA: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The issuing CA certificate.",
			},
			consts.FieldCAChain: {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The CA chain as a list of format specific certificates",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldCertificateBundle: {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The concatenation of the intermediate and issuing CA certificates (PEM encoded). " +
					"Requires the format to be set to any of: pem, " +
					"pem_bundle. The value will be empty for all other formats.",
			},
			consts.FieldSerial: {
				Type:        schema.TypeString,
				Computed:    true,
				Deprecated:  "Use serial_number instead",
				Description: "The serial number.",
			},
			consts.FieldSerialNumber: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certificate's serial number, hex formatted.",
			},
			consts.FieldRevoke: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Revoke the certificate upon resource destruction.",
			},
			consts.FieldIssuerRef: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the default issuer of this request.",
			},
		},
	}
}

func pkiSecretBackendRootSignIntermediateCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := pkiSecretBackendRootSignIntermediateCreatePath(backend)

	commonName := d.Get(consts.FieldCommonName).(string)

	intermediateSignAPIFields := []string{
		consts.FieldCSR,
		consts.FieldCommonName,
		consts.FieldTTL,
		consts.FieldFormat,
		consts.FieldMaxPathLength,
		consts.FieldOu,
		consts.FieldOrganization,
		consts.FieldCountry,
		consts.FieldLocality,
		consts.FieldProvince,
		consts.FieldStreetAddress,
		consts.FieldPostalCode,
	}

	intermediateSignBooleanAPIFields := []string{
		consts.FieldExcludeCNFromSans,
		consts.FieldUseCSRValues,
	}

	intermediateSignStringArrayFields := []string{
		consts.FieldAltNames,
		consts.FieldIPSans,
		consts.FieldURISans,
		consts.FieldOtherSans,
		consts.FieldPermittedDNSDomains,
	}

	data := map[string]interface{}{}
	for _, k := range intermediateSignAPIFields {
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

	// add boolean fields
	for _, k := range intermediateSignBooleanAPIFields {
		data[k] = d.Get(k)
	}

	// add comma separated string fields
	for _, k := range intermediateSignStringArrayFields {
		m := util.ToStringArray(d.Get(k).([]interface{}))
		if len(m) > 0 {
			data[k] = strings.Join(m, ",")
		}
	}

	log.Printf("[DEBUG] Creating root sign-intermediate on PKI secret backend %q", backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating root sign-intermediate on PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created root sign-intermediate on PKI secret backend %q", backend)

	// helpful to consolidate code into single loop
	// since 'serial' is deprecated, we read the 'serial_number'
	// field from the response in order to set to the TF state
	certFieldsMap := map[string]string{
		consts.FieldCertificate:  consts.FieldCertificate,
		consts.FieldIssuingCA:    consts.FieldIssuingCA,
		consts.FieldSerialNumber: consts.FieldSerialNumber,
		consts.FieldSerial:       consts.FieldSerialNumber,
	}

	for k, v := range certFieldsMap {
		if err := d.Set(k, resp.Data[v]); err != nil {
			return diag.FromErr(err)
		}
	}

	if err := setCAChain(d, resp); err != nil {
		return diag.FromErr(err)
	}

	if err := setCertificateBundle(d, resp); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(fmt.Sprintf("%s/%s", backend, commonName))

	return pkiSecretBackendRootSignIntermediateRead(ctx, d, meta)
}

func setCAChain(d *schema.ResourceData, resp *api.Secret) error {
	field := consts.FieldCAChain
	var caChain []string
	if v, ok := resp.Data[field]; ok && v != nil {
		switch v := v.(type) {
		case []interface{}:
			for _, v := range v {
				caChain = append(caChain, v.(string))
			}
		default:
			return fmt.Errorf("response contains an unexpected type %T for %q", v, field)
		}
	}

	// provide the CAChain from the issuing_ca and the intermediate CA certificate
	var err error
	if len(caChain) == 0 {
		caChain, err = getCAChain(resp.Data, !isPEMFormat(d))
		if err != nil {
			return err
		}
	}

	return d.Set(field, caChain)
}

func getCAChain(m map[string]interface{}, literal bool) ([]string, error) {
	return parseCertChain(m, true, literal)
}

func isPEMFormat(d *schema.ResourceData) bool {
	format := d.Get(consts.FieldFormat).(string)
	switch format {
	case "pem", "pem_bundle":
		return true
	default:
		return false
	}
}

func setCertificateBundle(d *schema.ResourceData, resp *api.Secret) error {
	field := consts.FieldCertificateBundle
	if !isPEMFormat(d) {
		log.Printf("[WARN] Cannot set the %q, not in PEM format", field)
		return nil
	}

	chain, err := parseCertChain(resp.Data, false, false)
	if err != nil {
		return err
	}

	return d.Set(field, strings.Join(chain, "\n"))
}

func parseCertChain(m map[string]interface{}, asCA, literal bool) ([]string, error) {
	var chain []string
	seen := make(map[string]bool)
	parseCert := func(data string) error {
		var b *pem.Block
		rest := []byte(data)
		for {
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}

			cert := strings.Trim(string(pem.EncodeToMemory(b)), "\n")
			if _, ok := seen[cert]; !ok {
				chain = append(chain, cert)
				seen[cert] = true
			}
		}

		return nil
	}

	fields := []string{consts.FieldIssuingCA, consts.FieldCertificate}
	if !asCA {
		fields = []string{fields[1], fields[0]}
	}

	for _, k := range fields {
		if v, ok := m[k]; ok && v.(string) != "" {
			value := v.(string)
			if literal {
				chain = append(chain, value)
			} else if err := parseCert(value); err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("required certificate for %q is missing or empty", k)
		}
	}

	return chain, nil
}

func pkiSecretBackendRootSignIntermediateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendRootSignIntermediateUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendRootSignIntermediateCreatePath(backend string) string {
	return strings.Trim(backend, "/") + "/root/sign-intermediate"
}

func pkiSecretRootSignIntermediateRV0() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldCAChain: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func pkiSecretRootSignIntermediateRUpgradeV0(
	_ context.Context, rawState map[string]interface{}, _ interface{},
) (map[string]interface{}, error) {
	caChain, err := getCAChain(rawState, false)
	if err != nil {
		return nil, err
	}
	rawState[consts.FieldCAChain] = caChain

	return rawState, nil
}
