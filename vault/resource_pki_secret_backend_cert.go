// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func pkiSecretBackendCertResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pkiSecretBackendCertCreate,
		ReadContext:   provider.ReadContextWrapper(pkiSecretBackendCertRead),
		UpdateContext: pkiSecretBackendCertUpdate,
		DeleteContext: pkiSecretBackendCertDelete,
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
			consts.FieldCommonName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "CN of the certificate to create.",
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
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The CA chain.",
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
			consts.FieldSerialNumber: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The serial number.",
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
			consts.FieldUserIds: {
				Type:        schema.TypeList,
				Optional:    true,
				ForceNew:    true,
				Description: "List of Subject User IDs.",
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
		},
	}
}

func pkiSecretBackendCertCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	name := d.Get(consts.FieldName).(string)

	path := pkiSecretBackendCertPath(backend, name)

	commonName := d.Get(consts.FieldCommonName).(string)

	certAPIFields := []string{
		consts.FieldCommonName,
		consts.FieldTTL,
		consts.FieldFormat,
		consts.FieldPrivateKeyFormat,
		consts.FieldNotAfter,
	}

	certBooleanAPIFields := []string{
		consts.FieldExcludeCNFromSans,
	}

	certStringArrayAPIFields := []string{
		consts.FieldAltNames,
		consts.FieldOtherSans,
		consts.FieldIPSans,
		consts.FieldURISans,
	}

	data := map[string]interface{}{}
	for _, k := range certAPIFields {
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

	// add UID if supported
	if provider.IsAPISupported(meta, provider.VaultVersion113) {
		if userIds, ok := d.GetOk(consts.FieldUserIds); ok {
			m := util.ToStringArray(userIds.([]interface{}))
			if len(m) > 0 {
				data[consts.FieldUserIds] = strings.Join(m, ",")
			}
		}
	}

	// add boolean fields
	for _, k := range certBooleanAPIFields {
		data[k] = d.Get(k)
	}

	// add comma separated string fields
	for _, k := range certStringArrayAPIFields {
		m := util.ToStringArray(d.Get(k).([]interface{}))
		if len(m) > 0 {
			data[k] = strings.Join(m, ",")
		}
	}

	log.Printf("[DEBUG] Creating certificate %s by %s on PKI secret backend %q", commonName, name, backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating certificate %s by %s for PKI secret backend %q: %s", commonName, name,
			backend, err)
	}
	log.Printf("[DEBUG] Created certificate %s by %s on PKI secret backend %q", commonName, name, backend)

	caChain := resp.Data[consts.FieldCAChain]
	if caChain != nil {
		d.Set(consts.FieldCAChain, strings.Join(convertIntoSliceOfString(caChain)[:], "\n"))
	}

	computedFields := []string{
		consts.FieldCertificate,
		consts.FieldIssuingCA,
		consts.FieldPrivateKey,
		consts.FieldPrivateKeyType,
		consts.FieldSerialNumber,
		consts.FieldExpiration,
	}

	for _, k := range computedFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	if err := pkiSecretBackendCertSynchronizeRenewPending(d); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(fmt.Sprintf("%s/%s/%s", backend, name, commonName))
	return pkiSecretBackendCertRead(ctx, d, meta)
}

func pkiCertAutoRenewCustomizeDiff(_ context.Context, d *schema.ResourceDiff, meta interface{}) error {
	// The Create and Read functions will both set renew_pending if
	// the current time is after the min_seconds_remaining timestamp. During
	// planning we respond to that by proposing automatic renewal, if enabled.
	if d.Id() == "" || !d.Get(consts.FieldAutoRenew).(bool) {
		return nil
	}
	if d.Get(consts.FieldRenewPending).(bool) {
		log.Printf("[DEBUG] certificate %q is due for renewal", d.Id())
		if err := d.SetNewComputed(consts.FieldCertificate); err != nil {
			return err
		}

		if err := d.ForceNew(consts.FieldCertificate); err != nil {
			return err
		}

		// Renewing the certificate will reset the value of renew_pending
		d.SetNewComputed(consts.FieldRenewPending)
		if err := d.ForceNew(consts.FieldRenewPending); err != nil {
			return err
		}

		return nil
	}

	log.Printf("[DEBUG] certificate %q is not due for renewal", d.Id())
	return nil
}

func pkiSecretBackendCertRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if d.IsNewResource() {
		return nil
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Get(consts.FieldBackend).(string)

	_, err := mountutil.GetMount(ctx, client, path)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found, removing from state.", path)
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	if err := pkiSecretBackendCertSynchronizeRenewPending(d); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func pkiSecretBackendCertUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// TODO: add mount gone detection
	return nil
}

func pkiSecretBackendCertDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if d.Get(consts.FieldRevoke).(bool) {
		client, e := provider.GetClient(d, meta)
		if e != nil {
			return diag.FromErr(e)
		}

		backend := d.Get(consts.FieldBackend).(string)
		path := strings.Trim(backend, "/") + "/revoke"

		serialNumber := d.Get(consts.FieldSerialNumber).(string)
		commonName := d.Get(consts.FieldCommonName).(string)
		data := map[string]interface{}{
			consts.FieldSerialNumber: serialNumber,
		}

		log.Printf("[DEBUG] Revoking certificate %q with serial number %q on PKI secret backend %q",
			commonName, serialNumber, backend)
		_, err := client.Logical().Write(path, data)
		if err != nil {
			return diag.Errorf("error revoking certificate %q with serial number %q for PKI secret backend %q: %s",
				commonName, serialNumber, backend, err)
		}
		log.Printf("[DEBUG] Successfully revoked certificate %q with serial number %q on PKI secret backend %q",
			commonName,
			serialNumber, backend)
	}

	return nil
}

func pkiSecretBackendCertPath(backend string, name string) string {
	return strings.Trim(backend, "/") + "/issue/" + strings.Trim(name, "/")
}

// pkiSecretBackendCertSynchronizeRenewPending calculates whether the
// expiration time of the certificate is fewer than min_seconds_remaining
// seconds in the future (relative to the current system time), and then
// updates the renew_pending attribute accordingly.
func pkiSecretBackendCertSynchronizeRenewPending(d *schema.ResourceData) error {
	if _, ok := d.Get(consts.FieldRenewPending).(bool); !ok {
		// pkiSecretBackendCertRead is shared between vault_pki_secret_backend_cert
		// and vault_pki_secret_backend_root_cert, and the latter doesn't have
		// an auto-renew mechanism so doesn't have a consts.FieldRenewPending attribute
		// to update.
		return nil
	}

	expiration := d.Get(consts.FieldExpiration).(int)
	earlyRenew := d.Get(consts.FieldMinSecondsRemaining).(int)
	effectiveExpiration := int64(expiration - earlyRenew)
	return d.Set(consts.FieldRenewPending, checkPKICertExpiry(effectiveExpiration))
}

func checkPKICertExpiry(expiration int64) bool {
	expiry := time.Unix(expiration, 0)
	now := time.Now()

	return now.After(expiry)
}

func convertIntoSliceOfString(slice interface{}) []string {
	intSlice := slice.([]interface{})
	strSlice := make([]string, len(intSlice))
	for i, v := range intSlice {
		strSlice[i] = v.(string)
	}
	return strSlice
}
