// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	issuerNotFoundErr = "unable to find PKI issuer for reference"
)

func pkiSecretBackendRootCertResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pkiSecretBackendRootCertCreate,
		DeleteContext: pkiSecretBackendRootCertDelete,
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
		CustomizeDiff: func(_ context.Context, d *schema.ResourceDiff, meta interface{}) error {
			key := consts.FieldSerialNumber
			o, _ := d.GetChange(key)
			// skip on new resource
			if o.(string) == "" {
				return nil
			}

			client, e := provider.GetClient(d, meta)
			if e != nil {
				return e
			}

			var cert *x509.Certificate
			isIssuerAPISupported := provider.IsAPISupported(meta, provider.VaultVersion111)
			if isIssuerAPISupported {
				// get the specific certificate for issuer with issuer_id
				cert, e = getIssuerPEM(client, d.Get(consts.FieldBackend).(string), d.Get(consts.FieldIssuerID).(string))
				if e != nil {
					// Check if this is an out-of-band change on the issuer
					if util.Is500(e) && util.ErrorContainsString(e, issuerNotFoundErr) {
						log.Printf("[WARN] issuer deleted out-of-band. re-creating root cert")
						// Force a change on the issuer ID field since
						// it no longer exists and must be re-created
						if e = d.SetNewComputed(consts.FieldIssuerID); e != nil {
							return e
						}

						if e := d.ForceNew(consts.FieldIssuerID); e != nil {
							return e
						}

						return nil
					}

					// not an out-of-band issuer error
					return e
				}
			} else {
				// get the 'default' issuer's certificate
				// default behavior for non multi-issuer API
				cert, e = getDefaultCAPEM(client, d.Get(consts.FieldBackend).(string))
				if e != nil {
					return e
				}
			}

			if cert != nil {
				n := certutil.GetHexFormatted(cert.SerialNumber.Bytes(), ":")
				if d.Get(key).(string) != n {
					if err := d.SetNewComputed(key); err != nil {
						return err
					}
					if err := d.ForceNew(key); err != nil {
						return err
					}
				}

			}

			return nil
		},

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
				Description:  "Type of root to create. Must be either \"existing\", \"exported\", \"internal\" or \"kms\"",
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{consts.FieldExisting, consts.FieldExported, consts.FieldInternal, keyTypeKMS}, false),
			},
			consts.FieldCommonName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "CN of root to create.",
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
			consts.FieldSignatureBits: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The number of bits to use in the signature algorithm.",
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
			consts.FieldPermittedDNSDomains: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of domains for which certificates are allowed to be issued.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldExcludedDNSDomains: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of domains for which certificates are not allowed to be issued.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldPermittedIPRanges: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of IP ranges for which certificates are allowed to be issued.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldExcludedIPRanges: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of IP ranges for which certificates are not allowed to be issued.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldPermittedEmailAddresses: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of email addresses for which certificates are allowed to be issued.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldExcludedEmailAddresses: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of email addresses for which certificates are not allowed to be issued.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldPermittedURIDomains: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of URI domains for which certificates are allowed to be issued.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldExcludedURIDomains: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of URI domains for which certificates are not allowed to be issued.",
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
				Description: "The certificate.",
			},
			consts.FieldIssuingCA: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The issuing CA.",
			},
			consts.FieldSerialNumber: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certificate's serial number, hex formatted.",
			},
			consts.FieldManagedKeyName: {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				Description:   "The name of the previously configured managed key.",
				ForceNew:      true,
				ConflictsWith: []string{consts.FieldManagedKeyID},
			},
			consts.FieldManagedKeyID: {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				Description:   "The ID of the previously configured managed key.",
				ForceNew:      true,
				ConflictsWith: []string{consts.FieldManagedKeyName},
			},
			consts.FieldIssuerName: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "Provides a name to the specified issuer. The name must be unique " +
					"across all issuers and not be the reserved value 'default'.",
				ForceNew: true,
			},
			consts.FieldIssuerID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The ID of the generated issuer.",
				ForceNew:    true,
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
			consts.FieldNotAfter: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Set the Not After field of the certificate with specified date value. " +
					"The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ. Supports the " +
					"Y10K end date for IEEE 802.1AR-2018 standard devices, 9999-12-31T23:59:59Z.",
			},
			consts.FieldNotBeforeDuration: {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  "Specifies the duration by which to backdate the NotBefore property. Defaults to 30s.",
				ForceNew:     true,
				ValidateFunc: provider.ValidateDuration,
			},
			consts.FieldUsePSS: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether to use PSS signatures when using a RSA key-type issuer.",
				ForceNew:    true,
			},
			consts.FieldKeyUsage: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specify the allowed key usage constraint on issued certificates.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func pkiSecretBackendRootCertCreate(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	rootType := d.Get(consts.FieldType).(string)

	path := pkiSecretBackendGenerateRootPath(backend, rootType, provider.IsAPISupported(meta, provider.VaultVersion111))

	rootCertAPIFields := []string{
		consts.FieldCommonName,
		consts.FieldTTL,
		consts.FieldFormat,
		consts.FieldPrivateKeyFormat,
		consts.FieldMaxPathLength,
		consts.FieldOu,
		consts.FieldOrganization,
		consts.FieldCountry,
		consts.FieldLocality,
		consts.FieldProvince,
		consts.FieldStreetAddress,
		consts.FieldPostalCode,
		consts.FieldManagedKeyName,
		consts.FieldManagedKeyID,
		consts.FieldSignatureBits,
		consts.FieldNotAfter,
		consts.FieldNotBeforeDuration,
	}

	rootCertBooleanAPIFields := []string{
		consts.FieldExcludeCNFromSans,
	}

	rootCertStringArrayFields := []string{
		consts.FieldAltNames,
		consts.FieldIPSans,
		consts.FieldURISans,
		consts.FieldOtherSans,
		consts.FieldPermittedDNSDomains,
	}

	// add multi-issuer write API fields if supported
	isIssuerAPISupported := provider.IsAPISupported(meta, provider.VaultVersion111)

	// Check if use_pss is supported (Vault 1.18.0+)
	isPSSSupported := provider.IsAPISupported(meta, provider.VaultVersion118)
	if isPSSSupported {
		rootCertBooleanAPIFields = append(rootCertBooleanAPIFields, consts.FieldUsePSS)
	}

	// Check if key_usage is supported (Vault 1.19.2+ due to bug fix)
	isKeyUsageSupported := provider.IsAPISupported(meta, provider.VaultVersion1192)

	// Fields only used when we are generating a key
	if !(rootType == keyTypeKMS || rootType == consts.FieldExisting) {
		rootCertAPIFields = append(rootCertAPIFields, consts.FieldKeyType, consts.FieldKeyBits)
	}

	if isIssuerAPISupported {
		// We always can specify the issuer name we are generating root certs
		rootCertAPIFields = append(rootCertAPIFields, consts.FieldIssuerName)

		if rootType == consts.FieldExisting {
			rootCertAPIFields = append(rootCertAPIFields, consts.FieldKeyRef)
		} else {
			rootCertAPIFields = append(rootCertAPIFields, consts.FieldKeyName)
		}
	}

	// Whether name constraints fields (other than permitted_dns_domains), are supproted,
	// See VAULT-32141.
	isNameConstraintsExtensionSupported := provider.IsAPISupported(meta, provider.VaultVersion119)
	if isNameConstraintsExtensionSupported {
		rootCertStringArrayFields = append(rootCertStringArrayFields,
			consts.FieldExcludedDNSDomains,
			consts.FieldPermittedIPRanges,
			consts.FieldExcludedIPRanges,
			consts.FieldPermittedEmailAddresses,
			consts.FieldExcludedEmailAddresses,
			consts.FieldPermittedURIDomains,
			consts.FieldExcludedURIDomains,
		)
	}
	data := map[string]interface{}{}
	rawConfig := d.GetRawConfig()
	for _, k := range rootCertAPIFields {
		if v := d.Get(k); !rawConfig.GetAttr(k).IsNull() {
			data[k] = v
		}
	}

	// add boolean fields
	for _, k := range rootCertBooleanAPIFields {
		data[k] = d.Get(k)
	}

	// add comma separated string fields
	for _, k := range rootCertStringArrayFields {
		m := util.ToStringArray(d.Get(k).([]interface{}))
		if len(m) > 0 {
			data[k] = strings.Join(m, ",")
		}
	}

	// handle key_usage as string array (not comma-separated)
	// only if Vault 1.19.2+ supports it (due to bug fix)
	if isKeyUsageSupported {
		if v, ok := d.GetOk(consts.FieldKeyUsage); ok {
			data[consts.FieldKeyUsage] = expandStringSlice(v.([]interface{}))
		}
	}

	log.Printf("[DEBUG] Creating root cert on PKI secret backend %q", backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating root cert for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created root cert on PKI secret backend %q", backend)

	certFieldsMap := map[string]string{
		consts.FieldCertificate:  consts.FieldCertificate,
		consts.FieldIssuingCA:    consts.FieldIssuingCA,
		consts.FieldSerialNumber: consts.FieldSerialNumber,
	}

	// multi-issuer API fields that are set to TF state
	// after a read from Vault
	multiIssuerAPIComputedFields := []string{
		consts.FieldIssuerID,
		consts.FieldKeyID,
	}

	if isIssuerAPISupported {
		// add multi-issuer read API fields to field map
		for _, k := range multiIssuerAPIComputedFields {
			certFieldsMap[k] = k
		}
	}

	for k, v := range certFieldsMap {
		if err := d.Set(k, resp.Data[v]); err != nil {
			return diag.FromErr(err)
		}
	}

	// Set default for not_before_duration if user didn't provide it
	// Vault applies a default of "30s" but doesn't return it in the response
	if rawConfig.GetAttr(consts.FieldNotBeforeDuration).IsNull() {
		if err := d.Set(consts.FieldNotBeforeDuration, "30s"); err != nil {
			return diag.FromErr(err)
		}
	}

	id := path
	if isIssuerAPISupported {
		// multiple root certs can be issued
		// ensure ID for each root_cert resource is unique
		issuerID := resp.Data[consts.FieldIssuerID]
		id = fmt.Sprintf("%s/issuer/%s", backend, issuerID)
	}

	d.SetId(id)

	return nil
}

func getCACertificate(client *api.Client, path string) (*x509.Certificate, error) {
	req := client.NewRequest(http.MethodGet, path)
	req.ClientToken = ""
	resp, err := client.RawRequest(req)
	if err != nil {
		if util.ErrorContainsHTTPCode(err, http.StatusNotFound, http.StatusForbidden) {
			return nil, nil
		}
		return nil, err
	}

	if resp == nil {
		return nil, fmt.Errorf("expected a response body, got nil response")
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	b, _ := pem.Decode(data)
	if b != nil {
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		return cert, nil
	}

	return nil, nil
}

func getDefaultCAPEM(client *api.Client, mount string) (*x509.Certificate, error) {
	path := fmt.Sprintf("/v1/%s/ca/pem", mount)
	return getCACertificate(client, path)
}

func getIssuerPEM(client *api.Client, mount, issuerID string) (*x509.Certificate, error) {
	path := fmt.Sprintf("/v1/%s/issuer/%s/pem", mount, issuerID)
	return getCACertificate(client, path)
}

func pkiSecretBackendRootCertDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)

	path := pkiSecretBackendDeleteRootPath(backend)

	if provider.IsAPISupported(meta, provider.VaultVersion111) {
		// @TODO can be removed in future versions of the Provider
		// this is added to allow a seamless upgrade for users
		// from v3.18.0/v3.19.0 of the Provider
		if !strings.Contains(d.Id(), "/root/generate/") {
			path = d.Id()
		}
	}

	log.Printf("[DEBUG] Deleting root cert from PKI secret backend %q", path)
	if _, err := client.Logical().Delete(path); err != nil {
		return diag.Errorf("error deleting root cert from PKI secret backend %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted root cert from PKI secret backend %q", path)
	return nil
}

func pkiSecretBackendGenerateRootPath(backend, rootType string, isMultiIssuerSupported bool) string {
	if isMultiIssuerSupported {
		return strings.Trim(backend, "/") + "/issuers/generate/root/" + strings.Trim(rootType, "/")
	}
	return strings.Trim(backend, "/") + "/root/generate/" + strings.Trim(rootType, "/")
}

func pkiSecretBackendDeleteRootPath(backend string) string {
	return strings.Trim(backend, "/") + "/root"
}

// Deprecated — internal-only. Removed in next major version bump
func pkiSecretSerialNumberResourceV0() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldSerialNumber: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}

// Deprecated — internal-only. Removed in next major version bump
func pkiSecretSerialNumberUpgradeV0(
	_ context.Context, rawState map[string]interface{}, _ interface{},
) (map[string]interface{}, error) {
	rawState[consts.FieldSerialNumber] = rawState[consts.FieldSerial]

	return rawState, nil
}
