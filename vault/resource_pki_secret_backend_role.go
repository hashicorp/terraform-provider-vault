// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/pki"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var (
	pkiSecretBackendRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/roles/.+$")
	pkiSecretBackendRoleNameFromPathRegex    = regexp.MustCompile("^.+/roles/(.+)$")
)

// Any new fields should probably not be added to these lists. Instead handle
// them separately within a provider.IsAPISupported guard
var pkiSecretFields = []string{
	consts.FieldAllowedDomainsTemplate,
	consts.FieldAllowedOtherSans,
	consts.FieldAllowedURISans,
	consts.FieldCountry,
	consts.FieldKeyBits,
	consts.FieldSignatureBits,
	consts.FieldKeyType,
	consts.FieldLocality,
	consts.FieldMaxTTL,
	consts.FieldNotBeforeDuration,
	consts.FieldOU,
	consts.FieldOrganization,
	consts.FieldPostalCode,
	consts.FieldProvince,
	consts.FieldStreetAddress,
	consts.FieldTTL,
	consts.FieldNotAfter,
}

var pkiSecretListFields = []string{
	consts.FieldAllowedDomains,
	consts.FieldAllowedSerialNumbers,
	consts.FieldExtKeyUsage,
	consts.FieldExtKeyUsageOIDs,
	consts.FieldCnValidations,
}

var pkiSecretBooleanFields = []string{
	consts.FieldAllowAnyName,
	consts.FieldAllowBareDomains,
	consts.FieldAllowGlobDomains,
	consts.FieldAllowIPSans,
	consts.FieldAllowLocalhost,
	consts.FieldAllowSubdomains,
	consts.FieldAllowWildcardCertificates,
	consts.FieldAllowedURISansTemplate,
	consts.FieldBasicConstraintsValidForNonCA,
	consts.FieldClientFlag,
	consts.FieldCodeSigningFlag,
	consts.FieldEmailProtectionFlag,
	consts.FieldEnforceHostnames,
	consts.FieldGenerateLease,
	consts.FieldNoStore,
	consts.FieldRequireCN,
	consts.FieldServerFlag,
	consts.FieldUseCSRCommonName,
	consts.FieldUseCSRSans,
}

func pkiSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pkiSecretBackendRoleCreate,
		ReadContext:   provider.ReadContextWrapper(pkiSecretBackendRoleRead),
		UpdateContext: pkiSecretBackendRoleUpdate,
		DeleteContext: pkiSecretBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the PKI secret backend the resource belongs to.",
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the role.",
			},
			consts.FieldIssuerRef: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the default issuer of this request.",
			},
			consts.FieldTTL: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The TTL.",
			},
			consts.FieldMaxTTL: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The maximum TTL.",
			},
			consts.FieldAllowLocalhost: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow certificates for localhost.",
				Default:     true,
			},
			consts.FieldAllowedDomains: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The domains of the role.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldAllowedDomainsTemplate: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to indicate that `allowed_domains` specifies a template expression (e.g. {{identity.entity.aliases.<mount accessor>.name}})",
				Default:     false,
			},
			consts.FieldAllowBareDomains: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow certificates matching the actual domain.",
				Default:     false,
			},
			consts.FieldAllowSubdomains: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow certificates matching subdomains.",
				Default:     false,
			},
			consts.FieldAllowGlobDomains: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow names containing glob patterns.",
				Default:     false,
			},
			consts.FieldAllowAnyName: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow any name",
				Default:     false,
			},
			consts.FieldEnforceHostnames: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow only valid host names",
				Default:     true,
			},
			consts.FieldAllowIPSans: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow IP SANs",
				Default:     true,
			},
			consts.FieldAllowedURISans: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "Defines allowed URI SANs",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldAllowedOtherSans: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "Defines allowed custom SANs",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldAllowedURISansTemplate: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Flag to indicate that `allowed_uri_sans` specifies a template expression (e.g. {{identity.entity.aliases.<mount accessor>.name}})",
			},
			consts.FieldAllowWildcardCertificates: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to allow wildcard certificates",
				Default:     true,
			},
			consts.FieldServerFlag: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to specify certificates for server use.",
				Default:     true,
			},
			consts.FieldClientFlag: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to specify certificates for client use.",
				Default:     true,
			},
			consts.FieldCodeSigningFlag: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to specify certificates for code signing use.",
				Default:     false,
			},
			consts.FieldEmailProtectionFlag: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to specify certificates for email protection use.",
				Default:     false,
			},
			consts.FieldKeyType: {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Description:  "The generated key type.",
				ValidateFunc: validation.StringInSlice([]string{"rsa", "ec", "ed25519", "any"}, false),
				Default:      "rsa",
			},
			consts.FieldKeyBits: {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "The number of bits of generated keys.",
				Default:     2048,
			},
			consts.FieldSignatureBits: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The number of bits to use in the signature algorithm.",
			},
			consts.FieldKeyUsage: {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "Specify the allowed key usage constraint on issued certificates.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldExtKeyUsage: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "Specify the allowed extended key usage constraint on issued certificates.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldExtKeyUsageOIDs: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "A list of extended key usage OIDs.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldUseCSRCommonName: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to use the CN in the CSR.",
				Default:     true,
			},
			consts.FieldUseCSRSans: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to use the SANs in the CSR.",
				Default:     true,
			},
			consts.FieldOU: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The organization unit of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldOrganization: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The organization of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldCountry: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The country of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldLocality: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The locality of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldProvince: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The province of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldStreetAddress: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The street address of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldPostalCode: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "The postal code of generated certificates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldGenerateLease: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to generate leases with certificates.",
				Default:     false,
			},
			consts.FieldNoStore: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to not store certificates in the storage backend.",
				Default:     false,
			},
			consts.FieldRequireCN: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to force CN usage.",
				Default:     true,
			},
			consts.FieldPolicyIdentifiers: {
				Type:          schema.TypeList,
				Required:      false,
				Optional:      true,
				Description:   "Specify the list of allowed policies OIDs.",
				ConflictsWith: []string{consts.FieldPolicyIdentifier},
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldPolicyIdentifier: {
				Type:          schema.TypeSet,
				Optional:      true,
				Description:   "Policy identifier block; can only be used with Vault 1.11+",
				ConflictsWith: []string{consts.FieldPolicyIdentifiers},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						consts.FieldOID: {
							Type:        schema.TypeString,
							Required:    true,
							Optional:    false,
							Description: "OID",
						},
						consts.FieldCPS: {
							Type:        schema.TypeString,
							Required:    false,
							Optional:    true,
							Description: "Optional CPS URL",
						},
						consts.FieldNotice: {
							Type:        schema.TypeString,
							Required:    false,
							Optional:    true,
							Description: "Optional notice",
						},
					},
				},
			},
			consts.FieldBasicConstraintsValidForNonCA: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Flag to mark basic constraints valid when issuing non-CA certificates.",
				Default:     false,
			},
			consts.FieldNotBeforeDuration: {
				Type:         schema.TypeString,
				Required:     false,
				Optional:     true,
				Computed:     true,
				Description:  "Specifies the duration by which to backdate the NotBefore property.",
				ValidateFunc: provider.ValidateDuration,
			},
			consts.FieldAllowedSerialNumbers: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Description: "Defines allowed Subject serial numbers.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldCnValidations: {
				Type:        schema.TypeList,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "Specify validations to run on the Common Name field of the certificate.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldAllowedUserIds: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "The allowed User ID's.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldNotAfter: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Set the Not After field of the certificate with specified date value. " +
					"The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ. Supports the " +
					"Y10K end date for IEEE 802.1AR-2018 standard devices, 9999-12-31T23:59:59Z.",
			},
			consts.FieldUsePSS: {
				Type:     schema.TypeBool,
				Optional: true,
				Description: "Specifies whether or not to use PSS signatures over PKCS#1v1.5 signatures " +
					"when a RSA-type issuer is used. Ignored for ECDSA/Ed25519 issuers.",
			},
			consts.FieldNoStoreMetadata: {
				Type:     schema.TypeBool,
				Optional: true,
				Description: "Allows metadata to be stored keyed on the certificate's serial number. " +
					"The field is independent of no_store, allowing metadata storage regardless of whether " +
					"certificates are stored. If true, metadata is not stored and an error is returned if the " +
					"metadata field is specified on issuance APIs",
			},
			consts.FieldSerialNumberSource: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "Specifies the source of the subject serial number. Valid values are json-csr (default) " +
					"or json. When set to json-csr, the subject serial number is taken from the serial_number " +
					"parameter and falls back to the serial number in the CSR. When set to json, the subject " +
					"serial number is taken from the serial_number parameter but will ignore any value in the CSR." +
					" For backwards compatibility an empty value for this field will default to the json-csr behavior.",
			},
		},
	}
}

func pkiSecretBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	name := d.Get(consts.FieldName).(string)

	path := pkiSecretBackendRolePath(backend, name)

	log.Printf("[DEBUG] Writing PKI secret backend role %q", path)

	data := map[string]interface{}{}

	// handle TypeList
	for _, k := range pkiSecretListFields {
		if v, ok := d.GetOk(k); ok {
			list := expandStringSlice(v.([]interface{}))

			if len(list) > 0 {
				data[k] = list
			}
		}
	}
	// special handling for key_usage because an empty array or array with
	// empty string means we do not want to specify key usage constraints
	if v, ok := d.GetOk(consts.FieldKeyUsage); ok {
		data[consts.FieldKeyUsage] = expandStringSlice(v.([]interface{}))
	} else {
		// check if we are an empty array or null (not set in config)
		val, _ := d.GetRawConfig().AsValueMap()[consts.FieldKeyUsage]
		if !val.IsNull() {
			// value was set as empty array in config
			data[consts.FieldKeyUsage] = make([]string, 0)
		}
	}

	// handle TypeBool
	for _, k := range pkiSecretBooleanFields {
		// use d.Get for booleans
		// see: https://discuss.hashicorp.com/t/terraform-sdk-usage-which-out-of-get-getok-getokexists-with-boolean/41815
		data[k] = d.Get(k)
	}

	// handle all other types
	for _, k := range pkiSecretFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	// handle any other special cases
	if policyIdentifiers, ok := d.GetOk(consts.FieldPolicyIdentifiers); ok {
		data[consts.FieldPolicyIdentifiers] = policyIdentifiers
	} else if policyIdentifierBlocksRaw, ok := d.GetOk(consts.FieldPolicyIdentifier); ok {
		data[consts.FieldPolicyIdentifiers] = pki.ReadPolicyIdentifierBlocks(policyIdentifierBlocksRaw.(*schema.Set))
	}

	if provider.IsAPISupported(meta, provider.VaultVersion111) {
		if issuerRef, ok := d.GetOk(consts.FieldIssuerRef); ok {
			data[consts.FieldIssuerRef] = issuerRef
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		if usePSS, ok := d.GetOk(consts.FieldUsePSS); ok {
			data[consts.FieldUsePSS] = usePSS
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion113) {
		if allowedUserIds, ok := d.GetOk(consts.FieldAllowedUserIds); ok {
			ifcList := allowedUserIds.([]interface{})
			list := make([]string, 0, len(ifcList))
			for _, ifc := range ifcList {
				list = append(list, ifc.(string))
			}

			if len(list) > 0 {
				data[consts.FieldAllowedUserIds] = list
			}
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion117) {
		if noStoreMetadata, ok := d.GetOk(consts.FieldNoStoreMetadata); ok {
			data[consts.FieldNoStoreMetadata] = noStoreMetadata
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		if serialNumberSource, ok := d.GetOk(consts.FieldSerialNumberSource); ok {
			data[consts.FieldSerialNumberSource] = serialNumberSource
		}
	}

	log.Printf("[DEBUG] Creating role %s on PKI secret backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating role %s for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created role %s on PKI backend %q", name, backend)

	d.SetId(path)
	return pkiSecretBackendRoleRead(ctx, d, meta)
}

func pkiSecretBackendRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	backend, err := pkiSecretBackendRoleBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing role %q because its ID is invalid", path)
		d.SetId("")
		return diag.Errorf("invalid role ID %q: %s", path, err)
	}

	name, err := pkiSecretBackendRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing role %q because its ID is invalid", path)
		d.SetId("")
		return diag.Errorf("invalid role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading role from %q", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read role from %q", path)
	if secret == nil {
		log.Printf("[WARN] Role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set(consts.FieldBackend, backend)
	d.Set(consts.FieldName, name)

	listFields := append(pkiSecretListFields, consts.FieldKeyUsage)
	// handle TypeList
	for _, k := range listFields {
		if list, ok := util.GetStringSliceFromSecret(secret, k); ok {
			if len(list) > 0 {
				d.Set(k, list)
			}
		}
	}

	// handle TypeBool
	for _, k := range pkiSecretBooleanFields {
		d.Set(k, secret.Data[k])
	}

	// handle all other types
	for _, k := range pkiSecretFields {
		// handle any special cases
		switch {
		case k == consts.FieldNotBeforeDuration:
			d.Set(k, flattenVaultDuration(secret.Data[k]))
		case k == consts.FieldKeyBits || k == consts.FieldSignatureBits:
			keyBits, err := secret.Data[k].(json.Number).Int64()
			if err != nil {
				return diag.Errorf("expected %s %q to be a number", k, secret.Data[k])
			}
			d.Set(k, keyBits)
		default:
			d.Set(k, secret.Data[k])
		}
	}

	// handle any other special cases
	var legacyPolicyIdentifiers []string = nil
	var newPolicyIdentifiers *schema.Set = nil
	if policyIdentifiersRaw, ok := secret.Data[consts.FieldPolicyIdentifiers]; ok {
		if policyIdentifiersRawList, ok := policyIdentifiersRaw.([]interface{}); ok {
			var err error
			legacyPolicyIdentifiers, newPolicyIdentifiers, err = pki.MakePkiPolicyIdentifiersListOrSet(policyIdentifiersRawList)
			if err != nil {
				return diag.FromErr(err)
			}
		}
	}

	if len(legacyPolicyIdentifiers) > 0 {
		d.Set(consts.FieldPolicyIdentifiers, legacyPolicyIdentifiers)
	} else {
		d.Set(consts.FieldPolicyIdentifier, newPolicyIdentifiers)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion111) {
		if issuerRef, ok := secret.Data[consts.FieldIssuerRef]; ok {
			d.Set(consts.FieldIssuerRef, issuerRef)
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		if usePSS, ok := secret.Data[consts.FieldUsePSS]; ok {
			err = d.Set(consts.FieldUsePSS, usePSS)
			if err != nil {
				return diag.FromErr(err)
			}
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion113) {
		if allowedUserIds, ok := secret.Data[consts.FieldAllowedUserIds]; ok {
			d.Set(consts.FieldAllowedUserIds, allowedUserIds)
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion117) {
		if noStoreMetadata, ok := secret.Data[consts.FieldNoStoreMetadata]; ok {
			err = d.Set(consts.FieldNoStoreMetadata, noStoreMetadata)
			if err != nil {
				return diag.FromErr(err)
			}
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		if serialNumberSource, ok := secret.Data[consts.FieldSerialNumberSource]; ok {
			err = d.Set(consts.FieldSerialNumberSource, serialNumberSource)
			if err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return nil
}

func pkiSecretBackendRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Updating PKI secret backend role %q", path)

	// handle TypeList
	data := map[string]interface{}{}
	for _, k := range pkiSecretListFields {
		if v, ok := d.GetOk(k); ok {
			list := expandStringSlice(v.([]interface{}))

			if len(list) > 0 {
				data[k] = list
			}
		}
	}
	// special handling for key_usage because an empty array or array with
	// empty string means we do not want to specify key usage constraints
	if v, ok := d.GetOk(consts.FieldKeyUsage); ok {
		data[consts.FieldKeyUsage] = expandStringSlice(v.([]interface{}))
	} else {
		// check if we are an empty array or null (not set in config)
		val, _ := d.GetRawConfig().AsValueMap()[consts.FieldKeyUsage]
		if !val.IsNull() {
			// value was set as empty array in config
			data[consts.FieldKeyUsage] = make([]string, 0)
		}
	}

	// handle TypeBool
	for _, k := range pkiSecretBooleanFields {
		data[k] = d.Get(k)
	}

	// handle all other types
	for _, k := range pkiSecretFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	// handle any special cases
	if policyIdentifiers, ok := d.GetOk(consts.FieldPolicyIdentifiers); ok {
		data[consts.FieldPolicyIdentifiers] = policyIdentifiers
	} else if policyIdentifierBlocksRaw, ok := d.GetOk(consts.FieldPolicyIdentifier); ok {
		data[consts.FieldPolicyIdentifiers] = pki.ReadPolicyIdentifierBlocks(policyIdentifierBlocksRaw.(*schema.Set))
	}

	if provider.IsAPISupported(meta, provider.VaultVersion111) {
		if issuerRef, ok := d.GetOk(consts.FieldIssuerRef); ok {
			data[consts.FieldIssuerRef] = issuerRef
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		if usePSS, ok := d.GetOk(consts.FieldUsePSS); ok {
			data[consts.FieldUsePSS] = usePSS
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion113) {
		if allowedUserIds, ok := d.GetOk(consts.FieldAllowedUserIds); ok {
			ifcList := allowedUserIds.([]interface{})
			list := make([]string, 0, len(ifcList))
			for _, ifc := range ifcList {
				list = append(list, ifc.(string))
			}

			if len(list) > 0 {
				data[consts.FieldAllowedUserIds] = list
			}
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion117) {
		if noStoreMetadata, ok := d.GetOk(consts.FieldNoStoreMetadata); ok {
			data[consts.FieldNoStoreMetadata] = noStoreMetadata
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		if serialNumberSource, ok := d.GetOk(consts.FieldSerialNumberSource); ok {
			data[consts.FieldSerialNumberSource] = serialNumberSource
		}
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error updating PKI secret backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated PKI secret backend role %q", path)

	return pkiSecretBackendRoleRead(ctx, d, meta)
}

func pkiSecretBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Deleting role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted role %q", path)
	return nil
}

func pkiSecretBackendRolePath(backend string, name string) string {
	return strings.Trim(backend, "/") + "/roles/" + strings.Trim(name, "/")
}

func pkiSecretBackendRoleNameFromPath(path string) (string, error) {
	if !pkiSecretBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := pkiSecretBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func pkiSecretBackendRoleBackendFromPath(path string) (string, error) {
	if !pkiSecretBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := pkiSecretBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
