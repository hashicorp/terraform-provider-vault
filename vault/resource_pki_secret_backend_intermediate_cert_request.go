// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const keyTypeKMS = "kms"

func pkiSecretBackendIntermediateCertRequestResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pkiSecretBackendIntermediateCertRequestCreate,
		ReadContext:   pkiSecretBackendIntermediateCertRequestRead,
		DeleteContext: pkiSecretBackendIntermediateCertRequestDelete,

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			consts.FieldType: {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Type of intermediate to create. Must be either \"existing\", \"exported\", \"internal\" or \"kms\"",
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{consts.FieldExisting, consts.FieldExported, consts.FieldInternal, keyTypeKMS}, false),
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
			consts.FieldFormat: {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The format of data.",
				ForceNew:     true,
				Default:      "pem",
				ValidateFunc: validation.StringInSlice([]string{"pem", "der", "pem_bundle"}, false),
			},
			consts.FieldPrivateKeyFormat: {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The private key format.",
				ForceNew:     true,
				Default:      "der",
				ValidateFunc: validation.StringInSlice([]string{"der", "pkcs8"}, false),
			},
			consts.FieldKeyType: {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The desired key type.",
				ForceNew:     true,
				Default:      "rsa",
				ValidateFunc: validation.StringInSlice([]string{"rsa", "ec", "ed25519"}, false),
			},
			consts.FieldKeyBits: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The number of bits to use.",
				ForceNew:    true,
				Default:     2048,
			},
			consts.FieldExcludeCNFromSans: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Flag to exclude CN from SANs.",
				ForceNew:    true,
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
			consts.FieldCSR: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The CSR.",
			},
			consts.FieldPrivateKey: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The private key.",
				Sensitive:   true,
			},
			consts.FieldPrivateKeyType: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The private key type.",
			},
			consts.FieldManagedKeyName: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The name of the previously configured managed key.",
				ForceNew:      true,
				ConflictsWith: []string{consts.FieldManagedKeyID},
			},
			consts.FieldManagedKeyID: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The ID of the previously configured managed key.",
				ForceNew:      true,
				ConflictsWith: []string{consts.FieldManagedKeyName},
			},
			consts.FieldAddBasicConstraints: {
				Type: schema.TypeBool,
				Description: `Set 'CA: true' in a Basic Constraints extension. Only needed as
a workaround in some compatibility scenarios with Active Directory Certificate Services.`,
				ForceNew: true,
				Default:  false,
				Optional: true,
			},
			consts.FieldKeyName: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "When a new key is created with this request, optionally specifies " +
					"the name for this.",
				ForceNew: true,
			},
			consts.FieldKeyRef: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the key to use for generating this request.",
				ForceNew:    true,
			},
			consts.FieldKeyID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The ID of the generated key.",
				ForceNew:    true,
			},
		},
	}
}

func pkiSecretBackendIntermediateCertRequestCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	intermediateType := d.Get(consts.FieldType).(string)

	path := pkiSecretBackendIntermediateGeneratePath(backend, intermediateType, provider.IsAPISupported(meta, provider.VaultVersion111))

	intermediateCertAPIFields := []string{
		consts.FieldCommonName,
		consts.FieldFormat,
		consts.FieldPrivateKeyFormat,
		consts.FieldOu,
		consts.FieldOrganization,
		consts.FieldCountry,
		consts.FieldLocality,
		consts.FieldProvince,
		consts.FieldStreetAddress,
		consts.FieldPostalCode,
		consts.FieldManagedKeyName,
		consts.FieldManagedKeyID,
	}

	intermediateCertBooleanAPIFields := []string{
		consts.FieldExcludeCNFromSans,
		consts.FieldAddBasicConstraints,
	}

	intermediateCertStringArrayFields := []string{
		consts.FieldAltNames,
		consts.FieldIPSans,
		consts.FieldURISans,
		consts.FieldOtherSans,
	}

	// add multi-issuer write API fields if supported
	isIssuerAPISupported := provider.IsAPISupported(meta, provider.VaultVersion111)

	// Fields only used when we are generating a key
	if !(intermediateType == keyTypeKMS || intermediateType == consts.FieldExisting) {
		intermediateCertAPIFields = append(intermediateCertAPIFields, consts.FieldKeyType, consts.FieldKeyBits)
	}

	if isIssuerAPISupported {
		// Note: CSR generation does not persist an issuer, just a key, so consts.FieldIssuerName is not supported
		if intermediateType == consts.FieldExisting {
			intermediateCertAPIFields = append(intermediateCertAPIFields, consts.FieldKeyRef)
		} else {
			intermediateCertAPIFields = append(intermediateCertAPIFields, consts.FieldKeyName)
		}
	}

	data := map[string]interface{}{}
	for _, k := range intermediateCertAPIFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	// add boolean fields
	for _, k := range intermediateCertBooleanAPIFields {
		data[k] = d.Get(k)
	}

	// add comma separated string fields
	for _, k := range intermediateCertStringArrayFields {
		m := util.ToStringArray(d.Get(k).([]interface{}))
		if len(m) > 0 {
			data[k] = strings.Join(m, ",")
		}
	}

	log.Printf("[DEBUG] Creating intermediate cert request on PKI secret backend %q", backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating intermediate cert request for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created intermediate cert request on PKI secret backend %q", backend)

	if err := d.Set(consts.FieldCSR, resp.Data[consts.FieldCSR]); err != nil {
		return diag.FromErr(err)
	}

	// multi-issuer API fields that are set to TF state
	// after a read from Vault
	multiIssuerAPIComputedFields := []string{
		consts.FieldKeyID,
	}

	if isIssuerAPISupported {
		for _, k := range multiIssuerAPIComputedFields {
			if err := d.Set(k, resp.Data[k]); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	if d.Get(consts.FieldType) == consts.FieldExported {
		if err := d.Set(consts.FieldPrivateKey, resp.Data[consts.FieldPrivateKey]); err != nil {
			return diag.FromErr(err)
		}

		if err := d.Set(consts.FieldPrivateKeyType, resp.Data[consts.FieldPrivateKeyType]); err != nil {
			return diag.FromErr(err)
		}

	}

	id := path
	if provider.IsAPISupported(meta, provider.VaultVersion111) {
		// multiple CSRs can be generated
		// ensure unique IDs
		uniqueSuffix := uuid.New()
		id = fmt.Sprintf("%s/%s", path, uniqueSuffix)
	}

	d.SetId(id)
	return pkiSecretBackendIntermediateCertRequestRead(ctx, d, meta)
}

func pkiSecretBackendIntermediateCertRequestRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendIntermediateCertRequestDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendIntermediateGeneratePath(backend, intermediateType string, isMultiIssuerSupported bool) string {
	if isMultiIssuerSupported {
		return strings.Trim(backend, "/") + "/issuers/generate/intermediate/" + strings.Trim(intermediateType, "/")
	}
	return strings.Trim(backend, "/") + "/intermediate/generate/" + strings.Trim(intermediateType, "/")
}
