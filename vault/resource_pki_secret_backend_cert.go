// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func pkiSecretBackendCertResource() *schema.Resource {
	return &schema.Resource{
		Create:        pkiSecretBackendCertCreate,
		Read:          ReadWrapper(pkiSecretBackendCertRead),
		Update:        pkiSecretBackendCertUpdate,
		Delete:        pkiSecretBackendCertDelete,
		CustomizeDiff: pkiCertAutoRenewCustomizeDiff,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role to create the certificate against.",
				ForceNew:    true,
			},
			"common_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "CN of the certificate to create.",
				ForceNew:    true,
			},
			"alt_names": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of alternative names.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ip_sans": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of alternative IPs.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"uri_sans": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of alternative URIs.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"other_sans": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of other SANs.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    false,
				Description: "Time to live.",
			},
			"format": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The format of data.",
				ForceNew:     true,
				Default:      "pem",
				ValidateFunc: validation.StringInSlice([]string{"pem", "der", "pem_bundle"}, false),
			},
			"private_key_format": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The private key format.",
				ForceNew:     true,
				Default:      "der",
				ValidateFunc: validation.StringInSlice([]string{"der", "pkcs8"}, false),
			},
			"exclude_cn_from_sans": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Flag to exclude CN from SANs.",
				ForceNew:    true,
			},
			"auto_renew": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If enabled, a new certificate will be generated if the expiration is within min_seconds_remaining",
			},
			"min_seconds_remaining": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     604800,
				Description: "Generate a new certificate when the expiration is within this number of seconds",
			},
			"certificate": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certicate.",
			},
			"issuing_ca": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The issuing CA.",
			},
			"ca_chain": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The CA chain.",
			},
			"private_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The private key.",
				Sensitive:   true,
			},
			"private_key_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The private key type.",
			},
			"serial_number": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The serial number.",
			},
			"expiration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The certificate expiration as a Unix-style timestamp.",
			},
			"renew_pending": {
				Type:     schema.TypeBool,
				Computed: true,
				Description: "Initially false, and then set to true during refresh once " +
					"the expiration is less than min_seconds_remaining in the future.",
			},
			"revoke": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Revoke the certificate upon resource destruction.",
			},
		},
	}
}

func pkiSecretBackendCertCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := pkiSecretBackendCertPath(backend, name)

	commonName := d.Get("common_name").(string)

	// TODO: cleanup this bit...
	iAltNames := d.Get("alt_names").([]interface{})
	altNames := make([]string, 0, len(iAltNames))
	for _, iAltName := range iAltNames {
		altNames = append(altNames, iAltName.(string))
	}

	iIPSans := d.Get("ip_sans").([]interface{})
	ipSans := make([]string, 0, len(iIPSans))
	for _, iIpSan := range iIPSans {
		ipSans = append(ipSans, iIpSan.(string))
	}

	iURISans := d.Get("uri_sans").([]interface{})
	uriSans := make([]string, 0, len(iURISans))
	for _, iUriSan := range iURISans {
		uriSans = append(uriSans, iUriSan.(string))
	}

	iOtherSans := d.Get("other_sans").([]interface{})
	otherSans := make([]string, 0, len(iOtherSans))
	for _, iOtherSan := range iOtherSans {
		otherSans = append(otherSans, iOtherSan.(string))
	}

	data := map[string]interface{}{
		"common_name":          d.Get("common_name").(string),
		"ttl":                  d.Get("ttl").(string),
		"format":               d.Get("format").(string),
		"private_key_format":   d.Get("private_key_format").(string),
		"exclude_cn_from_sans": d.Get("exclude_cn_from_sans").(bool),
	}

	if len(altNames) > 0 {
		data["alt_names"] = strings.Join(altNames, ",")
	}

	if len(ipSans) > 0 {
		data["ip_sans"] = strings.Join(ipSans, ",")
	}

	if len(uriSans) > 0 {
		data["uri_sans"] = strings.Join(uriSans, ",")
	}

	if len(otherSans) > 0 {
		data["other_sans"] = strings.Join(otherSans, ",")
	}

	log.Printf("[DEBUG] Creating certificate %s by %s on PKI secret backend %q", commonName, name, backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating certificate %s by %s for PKI secret backend %q: %s", commonName, name,
			backend, err)
	}
	log.Printf("[DEBUG] Created certificate %s by %s on PKI secret backend %q", commonName, name, backend)

	caChain := resp.Data["ca_chain"]
	if caChain != nil {
		d.Set("ca_chain", strings.Join(convertIntoSliceOfString(caChain)[:], "\n"))
	}

	d.Set("certificate", resp.Data["certificate"])
	d.Set("issuing_ca", resp.Data["issuing_ca"])
	d.Set("private_key", resp.Data["private_key"])
	d.Set("private_key_type", resp.Data["private_key_type"])
	d.Set("serial_number", resp.Data["serial_number"])
	d.Set("expiration", resp.Data["expiration"])

	if err := pkiSecretBackendCertSynchronizeRenewPending(d); err != nil {
		return err
	}

	d.SetId(fmt.Sprintf("%s/%s/%s", backend, name, commonName))
	return pkiSecretBackendCertRead(d, meta)
}

func pkiCertAutoRenewCustomizeDiff(_ context.Context, d *schema.ResourceDiff, meta interface{}) error {
	// The Create and Read functions will both set renew_pending if
	// the current time is after the min_seconds_remaining timestamp. During
	// planning we respond to that by proposing automatic renewal, if enabled.
	if d.Id() == "" || !d.Get("auto_renew").(bool) {
		return nil
	}
	if d.Get("renew_pending").(bool) {
		log.Printf("[DEBUG] certificate %q is due for renewal", d.Id())
		if err := d.SetNewComputed("certificate"); err != nil {
			return err
		}

		if err := d.ForceNew("certificate"); err != nil {
			return err
		}

		// Renewing the certificate will reset the value of renew_pending
		d.SetNewComputed("renew_pending")
		if err := d.ForceNew("renew_pending"); err != nil {
			return err
		}

		return nil
	}

	log.Printf("[DEBUG] certificate %q is not due for renewal", d.Id())
	return nil
}

func pkiSecretBackendCertRead(d *schema.ResourceData, meta interface{}) error {
	if d.IsNewResource() {
		return nil
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := d.Get("backend").(string)
	enabled, err := util.CheckMountEnabled(client, path)
	if err != nil {
		log.Printf("[WARN] Failed to check if mount %q exist, preempting the read operation", path)
		return nil
	}

	if enabled {
		if err := pkiSecretBackendCertSynchronizeRenewPending(d); err != nil {
			return err
		}
	} else {
		// trigger a resource re-creation whenever the engine's mount has disappeared
		log.Printf("[WARN] Mount %q does not exist, setting resource for re-creation", path)
		d.SetId("")
	}

	return nil
}

func pkiSecretBackendCertUpdate(d *schema.ResourceData, m interface{}) error {
	// TODO: add mount gone detection
	return nil
}

func pkiSecretBackendCertDelete(d *schema.ResourceData, meta interface{}) error {
	if d.Get("revoke").(bool) {
		client, e := provider.GetClient(d, meta)
		if e != nil {
			return e
		}

		backend := d.Get("backend").(string)
		path := strings.Trim(backend, "/") + "/revoke"

		serialNumber := d.Get("serial_number").(string)
		commonName := d.Get("common_name").(string)
		data := map[string]interface{}{
			"serial_number": serialNumber,
		}

		log.Printf("[DEBUG] Revoking certificate %q with serial number %q on PKI secret backend %q",
			commonName, serialNumber, backend)
		_, err := client.Logical().Write(path, data)
		if err != nil {
			return fmt.Errorf("error revoking certificate %q with serial number %q for PKI secret backend %q: %w",
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
	if _, ok := d.Get("renew_pending").(bool); !ok {
		// pkiSecretBackendCertRead is shared between vault_pki_secret_backend_cert
		// and vault_pki_secret_backend_root_cert, and the latter doesn't have
		// an auto-renew mechanism so doesn't have a "renew_pending" attribute
		// to update.
		return nil
	}

	expiration := d.Get("expiration").(int)
	earlyRenew := d.Get("min_seconds_remaining").(int)
	effectiveExpiration := int64(expiration - earlyRenew)
	return d.Set("renew_pending", checkPKICertExpiry(effectiveExpiration))
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
