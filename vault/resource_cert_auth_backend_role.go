// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldAllowedCommonNames         = "allowed_common_names"
	fieldAllowedDNSSans             = "allowed_dns_sans"
	fieldAllowedEmailSans           = "allowed_email_sans"
	fieldAllowedNames               = "allowed_names"
	fieldAllowedOrganizationUnits   = "allowed_organization_units"
	fieldAllowedOrganizationalUnits = "allowed_organizational_units"
	fieldAllowedURISans             = "allowed_uri_sans"
	fieldDisplayName                = "display_name"
	fieldOCSPCACertificates         = "ocsp_ca_certificates"
	fieldOCSPEnabled                = "ocsp_enabled"
	fieldOCSPFailOpen               = "ocsp_fail_open"
	fieldOCSPQueryAllServers        = "ocsp_query_all_servers"
	fieldOCSPServersOverride        = "ocsp_servers_override"
	fieldRequiredExtensions         = "required_extensions"
)

var (
	certAuthStringFields = []string{
		consts.FieldCertificate,
		fieldDisplayName,
		fieldOCSPCACertificates,
	}
	certAuthListFields = []string{
		fieldAllowedCommonNames,
		fieldAllowedDNSSans,
		fieldAllowedEmailSans,
		fieldAllowedNames,
		fieldAllowedOrganizationUnits,
		fieldAllowedOrganizationalUnits,
		fieldAllowedURISans,
		fieldOCSPServersOverride,
		fieldRequiredExtensions,
	}
	certAuthBoolFields = []string{
		fieldOCSPEnabled,
		fieldOCSPFailOpen,
		fieldOCSPQueryAllServers,
	}
)

func certAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldName: {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		consts.FieldCertificate: {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		fieldAllowedNames: {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		fieldAllowedCommonNames: {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		fieldAllowedDNSSans: {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		fieldAllowedEmailSans: {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		fieldAllowedURISans: {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		fieldAllowedOrganizationUnits: {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			Computed:      true,
			Deprecated:    "Use allowed_organizational_units",
			ConflictsWith: []string{"allowed_organizational_units"},
		},
		fieldAllowedOrganizationalUnits: {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			ConflictsWith: []string{"allowed_organization_units"},
		},
		fieldRequiredExtensions: {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		fieldDisplayName: {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		consts.FieldBackend: {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
			Default:  "cert",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		fieldOCSPCACertificates: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Any additional CA certificates needed to verify OCSP " +
				"responses. Provided as base64 encoded PEM data.",
		},
		fieldOCSPServersOverride: {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Description: "A comma-separated list of OCSP server addresses. If " +
				"unset, the OCSP server is determined from the " +
				"AuthorityInformationAccess extension on the certificate being inspected.",
		},
		fieldOCSPEnabled: {
			Type:        schema.TypeBool,
			Optional:    true,
			Computed:    true,
			Description: "If enabled, validate certificates' revocation status using OCSP.",
		},
		fieldOCSPFailOpen: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
			Description: "If true and an OCSP response cannot be fetched or is " +
				"of an unknown status, the login will proceed as if the certificate " +
				"has not been revoked.",
		},
		fieldOCSPQueryAllServers: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
			Description: "If set to true, rather than accepting the first " +
				"successful OCSP response, query all servers and consider the " +
				"certificate valid only if all servers agree.",
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		SchemaVersion: 1,

		CreateContext: certAuthResourceWrite,
		UpdateContext: certAuthResourceUpdate,
		ReadContext:   provider.ReadContextWrapper(certAuthResourceRead),
		DeleteContext: certAuthResourceDelete,
		Schema:        fields,
	}
}

func certCertResourcePath(backend, name string) string {
	return "auth/" + strings.Trim(backend, "/") + "/certs/" + strings.Trim(name, "/")
}

func certAuthResourceWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := certCertResourcePath(backend, name)

	data := map[string]interface{}{}
	updateTokenFields(d, data, true)

	for _, k := range certAuthStringFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	for _, k := range certAuthListFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v.(*schema.Set).List()
		}
	}

	for _, k := range certAuthBoolFields {
		data[k] = d.Get(k)
	}

	log.Printf("[DEBUG] Writing %q to cert auth backend", path)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("Error writing %q to cert auth backend: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote %q to cert auth backend", path)

	return certAuthResourceRead(ctx, d, meta)
}

func certAuthResourceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	data := map[string]interface{}{}
	updateTokenFields(d, data, false)

	for _, k := range certAuthStringFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	for _, k := range certAuthListFields {
		// special handling for allowed_organizational_units since unsetting
		// this in Vault has special meaning (allow all OUs)
		if k == fieldAllowedOrganizationalUnits {
			if d.HasChange(k) {
				data[k] = d.Get(k).(*schema.Set).List()
			}
		} else if v, ok := d.GetOk(k); ok {
			data[k] = v.(*schema.Set).List()
		}
	}

	for _, k := range certAuthBoolFields {
		data[k] = d.Get(k)
	}

	log.Printf("[DEBUG] Updating %q in cert auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("Error updating %q in cert auth backend: %s", path, err)
	}
	log.Printf("[DEBUG] Updated %q in cert auth backend", path)

	return certAuthResourceRead(ctx, d, meta)
}

func certAuthResourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Reading cert %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("Error reading cert %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read cert %q", path)

	if resp == nil {
		log.Printf("[WARN] cert %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	d.Set("certificate", resp.Data["certificate"])
	d.Set("display_name", resp.Data["display_name"])

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_names"] != nil {
		d.Set("allowed_names",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_names"].([]interface{})))
	} else {
		d.Set("allowed_names",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_dns_sans"] != nil {
		d.Set("allowed_dns_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_dns_sans"].([]interface{})))
	} else {
		d.Set("allowed_dns_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_email_sans"] != nil {
		d.Set("allowed_email_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_email_sans"].([]interface{})))
	} else {
		d.Set("allowed_email_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_uri_sans"] != nil {
		d.Set("allowed_uri_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_uri_sans"].([]interface{})))
	} else {
		d.Set("allowed_uri_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["required_extensions"] != nil {
		d.Set("required_extensions",
			schema.NewSet(
				schema.HashString, resp.Data["required_extensions"].([]interface{})))
	} else {
		d.Set("required_extensions",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	if err := d.Set("allowed_organizational_units", resp.Data["allowed_organizational_units"]); err != nil {
		return diag.FromErr(err)
	}

	ocspFields := []string{
		fieldOCSPCACertificates,
		fieldOCSPEnabled,
		fieldOCSPFailOpen,
		fieldOCSPQueryAllServers,
		fieldOCSPServersOverride,
	}
	for _, f := range ocspFields {
		if err := d.Set(f, resp.Data[f]); err != nil {
			return diag.FromErr(err)
		}
	}

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func certAuthResourceDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting cert %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("Error deleting cert %q", path)
	}
	log.Printf("[DEBUG] Deleted cert %q", path)

	return nil
}
