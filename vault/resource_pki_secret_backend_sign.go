// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendSignResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendSignCreate,
		Delete: pkiSecretBackendSignDelete,
		Update: func(data *schema.ResourceData, i interface{}) error {
			return nil
		},
		Read: ReadWrapper(pkiSecretBackendCertRead),
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
			"csr": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The CSR.",
				ForceNew:    true,
			},
			"common_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "CN of intermediate to create.",
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
			"other_sans": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of other SANs.",
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
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The CA chain.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"serial": {
				Type:        schema.TypeString,
				Computed:    true,
				Deprecated:  "Use serial_number instead",
				Description: "The serial number.",
			},
			"serial_number": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certificate's serial number, hex formatted.",
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
		},
	}
}

func pkiSecretBackendSignCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := pkiSecretBackendIssuePath(backend, name)

	commonName := d.Get("common_name").(string)

	iAltNames := d.Get("alt_names").([]interface{})
	altNames := make([]string, 0, len(iAltNames))
	for _, iAltName := range iAltNames {
		altNames = append(altNames, iAltName.(string))
	}

	iOtherSans := d.Get("other_sans").([]interface{})
	otherSans := make([]string, 0, len(iOtherSans))
	for _, iOtherSan := range iOtherSans {
		otherSans = append(otherSans, iOtherSan.(string))
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

	data := map[string]interface{}{
		"csr":                  d.Get("csr").(string),
		"common_name":          d.Get("common_name").(string),
		"ttl":                  d.Get("ttl").(string),
		"format":               d.Get("format").(string),
		"exclude_cn_from_sans": d.Get("exclude_cn_from_sans").(bool),
	}

	if len(altNames) > 0 {
		data["alt_names"] = strings.Join(altNames, ",")
	}

	if len(otherSans) > 0 {
		data["other_sans"] = strings.Join(otherSans, ",")
	}

	if len(ipSans) > 0 {
		data["ip_sans"] = strings.Join(ipSans, ",")
	}

	if len(uriSans) > 0 {
		data["uri_sans"] = strings.Join(uriSans, ",")
	}

	log.Printf("[DEBUG] Creating certificate sign %s by %s on PKI secret backend %q", commonName, name,
		backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating certificate sign %s by %s for PKI secret backend %q: %s",
			commonName, name, backend, err)
	}
	log.Printf("[DEBUG] Created certificate sign %s by %s on PKI secret backend %q", commonName, name,
		backend)

	d.Set("certificate", resp.Data["certificate"])
	d.Set("issuing_ca", resp.Data["issuing_ca"])
	d.Set("ca_chain", resp.Data["ca_chain"])
	d.Set("serial", resp.Data["serial_number"])
	d.Set("serial_number", resp.Data["serial_number"])
	d.Set("expiration", resp.Data["expiration"])

	if err := pkiSecretBackendCertSynchronizeRenewPending(d); err != nil {
		return err
	}

	d.SetId(fmt.Sprintf("%s/%s/%s", backend, name, commonName))

	return pkiSecretBackendCertRead(d, meta)
}

func pkiSecretBackendSignDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendIssuePath(backend string, name string) string {
	return strings.Trim(backend, "/") + "/sign/" + strings.Trim(name, "/")
}
