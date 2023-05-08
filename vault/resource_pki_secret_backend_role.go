// Copyright (c) HashiCorp, Inc.
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
)

var (
	pkiSecretBackendRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/roles/.+$")
	pkiSecretBackendRoleNameFromPathRegex    = regexp.MustCompile("^.+/roles/(.+)$")
)

func pkiSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pkiSecretBackendRoleCreate,
		ReadContext:   ReadContextWrapper(pkiSecretBackendRoleRead),
		UpdateContext: pkiSecretBackendRoleUpdate,
		DeleteContext: pkiSecretBackendRoleDelete,
		Exists:        pkiSecretBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
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
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
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

	// TODO: selectively configure the engine by replacing all of the d.Get()
	// calls with d.GetOk()
	// The current approach is inconsistent with the majority of the other resources.
	// It also sets a bad precedent for contributors.
	iAllowedDomains := d.Get(consts.FieldAllowedDomains).([]interface{})
	allowedDomains := make([]string, 0, len(iAllowedDomains))
	for _, iAllowedDomain := range iAllowedDomains {
		allowedDomains = append(allowedDomains, iAllowedDomain.(string))
	}

	iKeyUsage := d.Get(consts.FieldKeyUsage).([]interface{})
	keyUsage := make([]string, 0, len(iKeyUsage))
	for _, iUsage := range iKeyUsage {
		keyUsage = append(keyUsage, iUsage.(string))
	}

	iExtKeyUsage := d.Get(consts.FieldExtKeyUsage).([]interface{})
	extKeyUsage := make([]string, 0, len(iExtKeyUsage))
	for _, iUsage := range iExtKeyUsage {
		extKeyUsage = append(extKeyUsage, iUsage.(string))
	}

	iAllowedSerialNumbers := d.Get(consts.FieldAllowedSerialNumbers).([]interface{})
	allowedSerialNumbers := make([]string, 0, len(iAllowedSerialNumbers))
	for _, iSerialNumber := range iAllowedSerialNumbers {
		allowedSerialNumbers = append(allowedSerialNumbers, iSerialNumber.(string))
	}

	data := map[string]interface{}{
		consts.FieldTTL:                           d.Get(consts.FieldTTL),
		consts.FieldMaxTTL:                        d.Get(consts.FieldMaxTTL),
		consts.FieldAllowLocalhost:                d.Get(consts.FieldAllowLocalhost),
		consts.FieldAllowBareDomains:              d.Get(consts.FieldAllowBareDomains),
		consts.FieldAllowSubdomains:               d.Get(consts.FieldAllowSubdomains),
		consts.FieldAllowedDomainsTemplate:        d.Get(consts.FieldAllowedDomainsTemplate),
		consts.FieldAllowGlobDomains:              d.Get(consts.FieldAllowGlobDomains),
		consts.FieldAllowAnyName:                  d.Get(consts.FieldAllowAnyName),
		consts.FieldEnforceHostnames:              d.Get(consts.FieldEnforceHostnames),
		consts.FieldAllowIPSans:                   d.Get(consts.FieldAllowIPSans),
		consts.FieldAllowedURISans:                d.Get(consts.FieldAllowedURISans),
		consts.FieldAllowedOtherSans:              d.Get(consts.FieldAllowedOtherSans),
		consts.FieldServerFlag:                    d.Get(consts.FieldServerFlag),
		consts.FieldClientFlag:                    d.Get(consts.FieldClientFlag),
		consts.FieldCodeSigningFlag:               d.Get(consts.FieldCodeSigningFlag),
		consts.FieldEmailProtectionFlag:           d.Get(consts.FieldEmailProtectionFlag),
		consts.FieldKeyType:                       d.Get(consts.FieldKeyType),
		consts.FieldKeyBits:                       d.Get(consts.FieldKeyBits),
		consts.FieldUseCSRCommonName:              d.Get(consts.FieldUseCSRCommonName),
		consts.FieldUseCSRSans:                    d.Get(consts.FieldUseCSRSans),
		consts.FieldOU:                            d.Get(consts.FieldOU),
		consts.FieldOrganization:                  d.Get(consts.FieldOrganization),
		consts.FieldCountry:                       d.Get(consts.FieldCountry),
		consts.FieldLocality:                      d.Get(consts.FieldLocality),
		consts.FieldProvince:                      d.Get(consts.FieldProvince),
		consts.FieldStreetAddress:                 d.Get(consts.FieldStreetAddress),
		consts.FieldPostalCode:                    d.Get(consts.FieldPostalCode),
		consts.FieldGenerateLease:                 d.Get(consts.FieldGenerateLease),
		consts.FieldNoStore:                       d.Get(consts.FieldNoStore),
		consts.FieldRequireCN:                     d.Get(consts.FieldRequireCN),
		consts.FieldBasicConstraintsValidForNonCA: d.Get(consts.FieldBasicConstraintsValidForNonCA),
		consts.FieldNotBeforeDuration:             d.Get(consts.FieldNotBeforeDuration),
	}

	if len(allowedDomains) > 0 {
		data[consts.FieldAllowedDomains] = allowedDomains
	}

	if len(keyUsage) > 0 {
		data[consts.FieldKeyUsage] = keyUsage
	}

	if len(extKeyUsage) > 0 {
		data[consts.FieldExtKeyUsage] = extKeyUsage
	}

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

	if len(allowedSerialNumbers) > 0 {
		data[consts.FieldAllowedSerialNumbers] = allowedSerialNumbers
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

	iAllowedDomains := secret.Data[consts.FieldAllowedDomains].([]interface{})
	allowedDomains := make([]string, 0, len(iAllowedDomains))
	for _, iAllowedDomain := range iAllowedDomains {
		allowedDomains = append(allowedDomains, iAllowedDomain.(string))
	}

	keyBits, err := secret.Data[consts.FieldKeyBits].(json.Number).Int64()
	if err != nil {
		return diag.Errorf("expected key_bits %q to be a number, isn't", secret.Data[consts.FieldKeyBits])
	}

	iKeyUsage := secret.Data[consts.FieldKeyUsage].([]interface{})
	keyUsage := make([]string, 0, len(iKeyUsage))
	for _, iUsage := range iKeyUsage {
		keyUsage = append(keyUsage, iUsage.(string))
	}

	iExtKeyUsage := secret.Data[consts.FieldExtKeyUsage].([]interface{})
	extKeyUsage := make([]string, 0, len(iExtKeyUsage))
	for _, iUsage := range iExtKeyUsage {
		extKeyUsage = append(extKeyUsage, iUsage.(string))
	}

	if provider.IsAPISupported(meta, provider.VaultVersion111) {
		if issuerRef, ok := secret.Data[consts.FieldIssuerRef]; ok {
			d.Set(consts.FieldIssuerRef, issuerRef)
		}
	}

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

	notBeforeDuration := flattenVaultDuration(secret.Data[consts.FieldNotBeforeDuration])

	iAllowedSerialNumbers := secret.Data[consts.FieldAllowedSerialNumbers].([]interface{})
	allowedSerialNumbers := make([]string, 0, len(iAllowedSerialNumbers))
	for _, iSerialNumber := range iAllowedSerialNumbers {
		allowedSerialNumbers = append(allowedSerialNumbers, iSerialNumber.(string))
	}

	d.Set(consts.FieldBackend, backend)
	d.Set(consts.FieldName, name)
	d.Set(consts.FieldTTL, secret.Data[consts.FieldTTL])
	d.Set(consts.FieldMaxTTL, secret.Data[consts.FieldMaxTTL])
	d.Set(consts.FieldAllowLocalhost, secret.Data[consts.FieldAllowLocalhost])
	d.Set(consts.FieldAllowedDomains, allowedDomains)
	d.Set(consts.FieldAllowedDomainsTemplate, secret.Data[consts.FieldAllowedDomainsTemplate])
	d.Set(consts.FieldAllowBareDomains, secret.Data[consts.FieldAllowBareDomains])
	d.Set(consts.FieldAllowSubdomains, secret.Data[consts.FieldAllowSubdomains])
	d.Set(consts.FieldAllowGlobDomains, secret.Data[consts.FieldAllowGlobDomains])
	d.Set(consts.FieldAllowAnyName, secret.Data[consts.FieldAllowAnyName])
	d.Set(consts.FieldEnforceHostnames, secret.Data[consts.FieldEnforceHostnames])
	d.Set(consts.FieldAllowIPSans, secret.Data[consts.FieldAllowIPSans])
	d.Set(consts.FieldAllowedURISans, secret.Data[consts.FieldAllowedURISans])
	d.Set(consts.FieldAllowedOtherSans, secret.Data[consts.FieldAllowedOtherSans])
	d.Set(consts.FieldServerFlag, secret.Data[consts.FieldServerFlag])
	d.Set(consts.FieldClientFlag, secret.Data[consts.FieldClientFlag])
	d.Set(consts.FieldCodeSigningFlag, secret.Data[consts.FieldCodeSigningFlag])
	d.Set(consts.FieldEmailProtectionFlag, secret.Data[consts.FieldEmailProtectionFlag])
	d.Set(consts.FieldKeyType, secret.Data[consts.FieldKeyType])
	d.Set(consts.FieldKeyBits, keyBits)
	d.Set(consts.FieldKeyUsage, keyUsage)
	d.Set(consts.FieldExtKeyUsage, extKeyUsage)
	d.Set(consts.FieldUseCSRCommonName, secret.Data[consts.FieldUseCSRCommonName])
	d.Set(consts.FieldUseCSRSans, secret.Data[consts.FieldUseCSRSans])
	d.Set(consts.FieldOU, secret.Data[consts.FieldOU])
	d.Set(consts.FieldOrganization, secret.Data[consts.FieldOrganization])
	d.Set(consts.FieldCountry, secret.Data[consts.FieldCountry])
	d.Set(consts.FieldLocality, secret.Data[consts.FieldLocality])
	d.Set(consts.FieldProvince, secret.Data[consts.FieldProvince])
	d.Set(consts.FieldStreetAddress, secret.Data[consts.FieldStreetAddress])
	d.Set(consts.FieldPostalCode, secret.Data[consts.FieldPostalCode])
	d.Set(consts.FieldGenerateLease, secret.Data[consts.FieldGenerateLease])
	d.Set(consts.FieldNoStore, secret.Data[consts.FieldNoStore])
	d.Set(consts.FieldRequireCN, secret.Data[consts.FieldRequireCN])
	if len(legacyPolicyIdentifiers) > 0 {
		d.Set(consts.FieldPolicyIdentifiers, legacyPolicyIdentifiers)
	} else {
		d.Set(consts.FieldPolicyIdentifier, newPolicyIdentifiers)
	}
	d.Set(consts.FieldBasicConstraintsValidForNonCA, secret.Data[consts.FieldBasicConstraintsValidForNonCA])
	d.Set(consts.FieldNotBeforeDuration, notBeforeDuration)
	d.Set(consts.FieldAllowedSerialNumbers, allowedSerialNumbers)

	return nil
}

func pkiSecretBackendRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Updating PKI secret backend role %q", path)

	iAllowedDomains := d.Get(consts.FieldAllowedDomains).([]interface{})
	allowedDomains := make([]string, 0, len(iAllowedDomains))
	for _, iAllowedDomain := range iAllowedDomains {
		allowedDomains = append(allowedDomains, iAllowedDomain.(string))
	}

	iKeyUsage := d.Get(consts.FieldKeyUsage).([]interface{})
	keyUsage := make([]string, 0, len(iKeyUsage))
	for _, iUsage := range iKeyUsage {
		keyUsage = append(keyUsage, iUsage.(string))
	}

	iExtKeyUsage := d.Get(consts.FieldExtKeyUsage).([]interface{})
	extKeyUsage := make([]string, 0, len(iExtKeyUsage))
	for _, iUsage := range iExtKeyUsage {
		extKeyUsage = append(extKeyUsage, iUsage.(string))
	}

	iAllowedSerialNumbers := d.Get(consts.FieldAllowedSerialNumbers).([]interface{})
	allowedSerialNumbers := make([]string, 0, len(iAllowedSerialNumbers))
	for _, iSerialNumber := range iAllowedSerialNumbers {
		allowedSerialNumbers = append(allowedSerialNumbers, iSerialNumber.(string))
	}

	data := map[string]interface{}{
		consts.FieldTTL:                           d.Get(consts.FieldTTL),
		consts.FieldMaxTTL:                        d.Get(consts.FieldMaxTTL),
		consts.FieldAllowLocalhost:                d.Get(consts.FieldAllowLocalhost),
		consts.FieldAllowBareDomains:              d.Get(consts.FieldAllowBareDomains),
		consts.FieldAllowedDomainsTemplate:        d.Get(consts.FieldAllowedDomainsTemplate),
		consts.FieldAllowSubdomains:               d.Get(consts.FieldAllowSubdomains),
		consts.FieldAllowGlobDomains:              d.Get(consts.FieldAllowGlobDomains),
		consts.FieldAllowAnyName:                  d.Get(consts.FieldAllowAnyName),
		consts.FieldEnforceHostnames:              d.Get(consts.FieldEnforceHostnames),
		consts.FieldAllowIPSans:                   d.Get(consts.FieldAllowIPSans),
		consts.FieldAllowedURISans:                d.Get(consts.FieldAllowedURISans),
		consts.FieldAllowedOtherSans:              d.Get(consts.FieldAllowedOtherSans),
		consts.FieldServerFlag:                    d.Get(consts.FieldServerFlag),
		consts.FieldClientFlag:                    d.Get(consts.FieldClientFlag),
		consts.FieldCodeSigningFlag:               d.Get(consts.FieldCodeSigningFlag),
		consts.FieldEmailProtectionFlag:           d.Get(consts.FieldEmailProtectionFlag),
		consts.FieldKeyType:                       d.Get(consts.FieldKeyType),
		consts.FieldKeyBits:                       d.Get(consts.FieldKeyBits),
		consts.FieldUseCSRCommonName:              d.Get(consts.FieldUseCSRCommonName),
		consts.FieldUseCSRSans:                    d.Get(consts.FieldUseCSRSans),
		consts.FieldOU:                            d.Get(consts.FieldOU),
		consts.FieldOrganization:                  d.Get(consts.FieldOrganization),
		consts.FieldCountry:                       d.Get(consts.FieldCountry),
		consts.FieldLocality:                      d.Get(consts.FieldLocality),
		consts.FieldProvince:                      d.Get(consts.FieldProvince),
		consts.FieldStreetAddress:                 d.Get(consts.FieldStreetAddress),
		consts.FieldPostalCode:                    d.Get(consts.FieldPostalCode),
		consts.FieldGenerateLease:                 d.Get(consts.FieldGenerateLease),
		consts.FieldNoStore:                       d.Get(consts.FieldNoStore),
		consts.FieldRequireCN:                     d.Get(consts.FieldRequireCN),
		consts.FieldBasicConstraintsValidForNonCA: d.Get(consts.FieldBasicConstraintsValidForNonCA),
		consts.FieldNotBeforeDuration:             d.Get(consts.FieldNotBeforeDuration),
	}

	if len(allowedDomains) > 0 {
		data[consts.FieldAllowedDomains] = allowedDomains
	}

	if len(keyUsage) > 0 {
		data[consts.FieldKeyUsage] = keyUsage
	}

	if len(extKeyUsage) > 0 {
		data[consts.FieldExtKeyUsage] = extKeyUsage
	}

	if provider.IsAPISupported(meta, provider.VaultVersion111) {
		if issuerRef, ok := d.GetOk(consts.FieldIssuerRef); ok {
			data[consts.FieldIssuerRef] = issuerRef
		}
	}

	if policyIdentifiers, ok := d.GetOk(consts.FieldPolicyIdentifiers); ok {
		data[consts.FieldPolicyIdentifiers] = policyIdentifiers
	} else if policyIdentifierBlocksRaw, ok := d.GetOk(consts.FieldPolicyIdentifier); ok {
		data[consts.FieldPolicyIdentifiers] = pki.ReadPolicyIdentifierBlocks(policyIdentifierBlocksRaw.(*schema.Set))
	}

	if len(allowedSerialNumbers) > 0 {
		data[consts.FieldAllowedSerialNumbers] = allowedSerialNumbers
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

func pkiSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if role %q exists", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if role %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if role %q exists", path)
	return secret != nil, nil
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
