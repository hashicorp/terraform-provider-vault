// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	pkiExtCAMountFromAcmeAccountPathRegex = regexp.MustCompile(`^(.+)/config/acme-account/.+$`)
	pkiExtCAAcmeAccountNameFromPathRegex  = regexp.MustCompile(`^.+/config/acme-account/(.+)$`)
)

func pkiExternalCASecretBackendAcmeAccountResource() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages Vault PKI ACME account bindings",
		CreateContext: pkiExternalCASecretBackendAcmeAccountCreate,
		ReadContext:   pkiExternalCASecretBackendAcmeAccountRead,
		DeleteContext: pkiExternalCASecretBackendAcmeAccountDelete,
		UpdateContext: pkiExternalCASecretBackendAcmeAccountUpdate,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldMount: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path where the PKI External CA secret backend is mounted.",
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the ACME account. Must be unique.",
			},
			consts.FieldDirectoryUrl: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ACME Directory URL for the Certificate Authority.",
			},
			consts.FieldEmailContacts: {
				Type:        schema.TypeList,
				Required:    true,
				Description: "List of email addresses for the ACME account.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldKeyType: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "ec-256",
				Description: "Key type for the account key. Valid values: ec-256, ec-384, ec-521, rsa-2048, rsa-4096, rsa-8192.",
			},
			consts.FieldEabKid: {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "External account binding key ID. Write-only.",
			},
			consts.FieldCAEabKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "External account binding HMAC key. Write-only.",
			},
			consts.FieldTrustedCA: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PEM-encoded trusted CA certificates for the ACME server.",
			},
			consts.FieldActiveKeyVersion: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Version of the active account key.",
			},
		},
	}
}

func pkiExternalCASecretBackendAcmeAccountUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	data := map[string]interface{}{}

	updateFields := []string{
		consts.FieldDirectoryUrl,
		consts.FieldEmailContacts,
		consts.FieldKeyType,
		consts.FieldTrustedCA,
	}
	for _, k := range updateFields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}
	// write-only fields: only send if they changed
	if d.HasChange(consts.FieldEabKid) {
		data[consts.FieldEabKid] = d.Get(consts.FieldEabKid)
	}
	if d.HasChange(consts.FieldCAEabKey) {
		data[consts.FieldCAEabKey] = d.Get(consts.FieldCAEabKey)
	}

	if len(data) > 0 {
		log.Printf("[DEBUG] Updating PKI External CA ACME account at %q", path)
		_, err := client.Logical().WriteWithContext(ctx, path, data)
		if err != nil {
			return diag.Errorf("error updating ACME account at %q: %s", path, err)
		}
	}

	return pkiExternalCASecretBackendAcmeAccountRead(ctx, d, meta)
}

func pkiExternalCASecretBackendAcmeAccountCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	mount := d.Get(consts.FieldMount).(string)
	name := d.Get(consts.FieldName).(string)
	path := fmt.Sprintf("%s/config/acme-account/%s", mount, name)
	data := map[string]interface{}{
		consts.FieldDirectoryUrl:  d.Get(consts.FieldDirectoryUrl),
		consts.FieldEmailContacts: d.Get(consts.FieldEmailContacts),
	}
	if v, ok := d.GetOk(consts.FieldKeyType); ok {
		data[consts.FieldKeyType] = v
	}
	if v, ok := d.GetOk(consts.FieldEabKid); ok {
		data[consts.FieldEabKid] = v
	}
	if v, ok := d.GetOk(consts.FieldCAEabKey); ok {
		data[consts.FieldCAEabKey] = v
	}
	if v, ok := d.GetOk(consts.FieldTrustedCA); ok {
		data[consts.FieldTrustedCA] = v
	}
	log.Printf("[DEBUG] Creating PKI External CA ACME account at %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error creating ACME account at %q: %s", path, err)
	}

	d.SetId(path)

	return pkiExternalCASecretBackendAcmeAccountRead(ctx, d, meta)
}

func pkiExternalCASecretBackendAcmeAccountRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	mount, name, err := pkiExtCAParseAcmeAccountPath(path)
	if err != nil {
		return diag.FromErr(err)
	}

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading ACME account at %q: %s", path, err)
	}
	if resp == nil {
		log.Printf("[WARN] ACME account not found at %q, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldMount, mount); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	// Read back non-sensitive fields from Vault response
	readFields := []string{
		consts.FieldDirectoryUrl,
		consts.FieldEmailContacts,
		consts.FieldKeyType,
		consts.FieldTrustedCA,
		consts.FieldActiveKeyVersion,
	}
	for _, k := range readFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error setting %q: %s", k, err)
			}
		}
	}

	return nil

}

func pkiExternalCASecretBackendAcmeAccountDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()
	log.Printf("[DEBUG] Deleting PKI External CA ACME account at %q", path)
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error deleting ACME account at %q: %s", path, err)
	}

	return nil
}

func pkiExtCAParseAcmeAccountPath(path string) (mount, name string, err error) {
	mountRes := pkiExtCAMountFromAcmeAccountPathRegex.FindStringSubmatch(path)
	if len(mountRes) != 2 {
		return "", "", fmt.Errorf("could not parse mount from path %q", path)
	}
	nameRes := pkiExtCAAcmeAccountNameFromPathRegex.FindStringSubmatch(path)
	if len(nameRes) != 2 {
		return "", "", fmt.Errorf("could not parse account name from path %q", path)
	}
	return mountRes[1], nameRes[1], nil
}
