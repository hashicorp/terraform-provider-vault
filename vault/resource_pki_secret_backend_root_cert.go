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

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func pkiSecretBackendRootCertResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendRootCertCreate,
		Delete: pkiSecretBackendRootCertDelete,
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
		CustomizeDiff: func(_ context.Context, d *schema.ResourceDiff, meta interface{}) error {
			key := "serial"
			o, _ := d.GetChange(key)
			// skip on new resource
			if o.(string) == "" {
				return nil
			}

			client, e := provider.GetClient(d, meta)
			if e != nil {
				return e
			}

			cert, err := getCACertificate(client, d.Get("backend").(string))
			if err != nil {
				return err
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
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			"type": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Type of root to create. Must be either \"exported\" or \"internal\".",
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"exported", "internal", "kms"}, false),
			},
			"common_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "CN of root to create.",
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
			"key_type": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The desired key type.",
				ForceNew:     true,
				Default:      "rsa",
				ValidateFunc: validation.StringInSlice([]string{"rsa", "ec", "ed25519"}, false),
			},
			"key_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The number of bits to use.",
				ForceNew:    true,
				Default:     2048,
			},
			"max_path_length": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The maximum path length to encode in the generated certificate.",
				ForceNew:    true,
				Default:     -1,
			},
			"exclude_cn_from_sans": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Flag to exclude CN from SANs.",
				ForceNew:    true,
			},
			"permitted_dns_domains": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of domains for which certificates are allowed to be issued.",
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ou": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The organization unit.",
				ForceNew:    true,
			},
			"organization": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The organization.",
				ForceNew:    true,
			},
			"country": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The country.",
				ForceNew:    true,
			},
			"locality": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The locality.",
				ForceNew:    true,
			},
			"province": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The province.",
				ForceNew:    true,
			},
			"street_address": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The street address.",
				ForceNew:    true,
			},
			"postal_code": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The postal code.",
				ForceNew:    true,
			},
			"certificate": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certificate.",
			},
			"issuing_ca": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The issuing CA.",
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
			"managed_key_name": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				Description:   "The name of the previously configured managed key.",
				ForceNew:      true,
				ConflictsWith: []string{"managed_key_id"},
			},
			"managed_key_id": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				Description:   "The ID of the previously configured managed key.",
				ForceNew:      true,
				ConflictsWith: []string{"managed_key_name"},
			},
		},
	}
}

func pkiSecretBackendRootCertCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	rootType := d.Get("type").(string)

	path := pkiSecretBackendIntermediateSetSignedReadPath(backend, rootType)

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

	iPermittedDNSDomains := d.Get("permitted_dns_domains").([]interface{})
	permittedDNSDomains := make([]string, 0, len(iPermittedDNSDomains))
	for _, iPermittedDNSDomain := range iPermittedDNSDomains {
		permittedDNSDomains = append(permittedDNSDomains, iPermittedDNSDomain.(string))
	}

	data := map[string]interface{}{
		"common_name":          d.Get("common_name").(string),
		"ttl":                  d.Get("ttl").(string),
		"format":               d.Get("format").(string),
		"private_key_format":   d.Get("private_key_format").(string),
		"max_path_length":      d.Get("max_path_length").(int),
		"exclude_cn_from_sans": d.Get("exclude_cn_from_sans").(bool),
		"ou":                   d.Get("ou").(string),
		"organization":         d.Get("organization").(string),
		"country":              d.Get("country").(string),
		"locality":             d.Get("locality").(string),
		"province":             d.Get("province").(string),
		"street_address":       d.Get("street_address").(string),
		"postal_code":          d.Get("postal_code").(string),
		"managed_key_name":     d.Get("managed_key_name").(string),
		"managed_key_id":       d.Get("managed_key_id").(string),
	}

	if rootType != "kms" {
		data["key_type"] = d.Get("key_type").(string)
		data["key_bits"] = d.Get("key_bits").(int)
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

	if len(permittedDNSDomains) > 0 {
		data["permitted_dns_domains"] = strings.Join(permittedDNSDomains, ",")
	}

	log.Printf("[DEBUG] Creating root cert on PKI secret backend %q", backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating root cert for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created root cert on PKI secret backend %q", backend)

	d.Set("certificate", resp.Data["certificate"])
	d.Set("issuing_ca", resp.Data["issuing_ca"])
	d.Set("serial", resp.Data["serial_number"])
	d.Set("serial_number", resp.Data["serial_number"])

	d.SetId(path)

	return nil
}

func getCACertificate(client *api.Client, mount string) (*x509.Certificate, error) {
	path := fmt.Sprintf("/v1/%s/ca/pem", mount)
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

func pkiSecretBackendRootCertDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)

	path := pkiSecretBackendIntermediateSetSignedDeletePath(backend)

	log.Printf("[DEBUG] Deleting root cert from PKI secret backend %q", path)
	if _, err := client.Logical().Delete(path); err != nil {
		return fmt.Errorf("error deleting root cert from PKI secret backend %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted root cert from PKI secret backend %q", path)
	return nil
}

func pkiSecretBackendIntermediateSetSignedReadPath(backend string, rootType string) string {
	return strings.Trim(backend, "/") + "/root/generate/" + strings.Trim(rootType, "/")
}

func pkiSecretBackendIntermediateSetSignedDeletePath(backend string) string {
	return strings.Trim(backend, "/") + "/root"
}

func pkiSecretSerialNumberResourceV0() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"serial_number": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func pkiSecretSerialNumberUpgradeV0(
	_ context.Context, rawState map[string]interface{}, _ interface{},
) (map[string]interface{}, error) {
	rawState["serial_number"] = rawState["serial"]

	return rawState, nil
}
