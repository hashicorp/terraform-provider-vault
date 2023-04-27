// Copyright (c) HashiCorp, Inc.
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
	kmsType = "kms"

	pkiSecretMountFromPathRegex = regexp.MustCompile("^(.+)/key/.+$")
	pkiSecretKeyIDFromPathRegex = regexp.MustCompile("^.+/key/(.+)$")
)

func pkiSecretBackendKeyResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: MountCreateContextWrapper(pkiSecretBackendKeyWrite, provider.VaultVersion111),
		UpdateContext: pkiSecretBackendKeyWrite,
		DeleteContext: pkiSecretBackendKeyDelete,
		ReadContext:   ReadContextWrapper(ReadContextWrapper(pkiSecretBackendKeyRead)),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldMount: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where PKI engine is mounted.",
			},
			consts.FieldType: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Specifies the type of the key to create.",
			},
			consts.FieldKeyName: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "When a new key is created with this request, optionally specifies the name for this.",
			},
			consts.FieldKeyType: {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Specifies the desired key type; must be 'rsa', 'ed25519' or 'ec'.",
			},
			consts.FieldKeyBits: {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Description: "Specifies the number of bits to use for the generated keys.",
			},
			consts.FieldKeyID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the generated key.",
			},
			consts.FieldManagedKeyName: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The managed key's configured name.",
			},
			consts.FieldManagedKeyID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The managed key's UUID.",
			},
		},
	}
}

func getPKIGenerateKeysPath(mount, keyType string) string {
	return fmt.Sprintf("%s/keys/generate/%s", mount, keyType)
}

func getPKIKeysIDPath(mount, keyID string) string {
	return fmt.Sprintf("%s/key/%s", mount, keyID)
}

func pkiSecretBackendKeyWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	mount := d.Get(consts.FieldMount).(string)
	keyType := d.Get(consts.FieldType).(string)
	keyPath := getPKIGenerateKeysPath(mount, keyType)

	fields := []string{
		consts.FieldKeyName,
		consts.FieldKeyType,
		consts.FieldKeyBits,
	}

	if keyType == kmsType {
		fields = append(fields, consts.FieldManagedKeyName, consts.FieldManagedKeyID)
	}

	data := map[string]interface{}{}
	for _, k := range fields {
		data[k] = d.Get(k)
	}

	resp, err := client.Logical().Write(keyPath, data)
	if err != nil {
		return diag.Errorf("error writing data to %q, err=%s", keyPath, err)
	}

	keyID := resp.Data[consts.FieldKeyID].(string)

	// set key ID path
	// this makes both mount and key ID info available
	rid := getPKIKeysIDPath(mount, keyID)
	d.SetId(rid)

	return pkiSecretBackendKeyRead(ctx, d, meta)
}

func pkiSecretBackendKeyRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	keyPath := d.Id()

	// get mount from full path
	mount, err := pkiSecretMountFromPath(keyPath)
	if err != nil {
		return diag.FromErr(err)
	}

	keyID, err := pkiSecretKeyIDFromPath(keyPath)
	if err != nil {
		return diag.FromErr(err)
	}

	// set mount and keyID
	if err := d.Set(consts.FieldMount, mount); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldKeyID, keyID); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading %s from Vault", keyPath)
	resp, err := client.Logical().Read(keyPath)
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}
	if resp == nil {
		log.Printf("[WARN] key data (%s) not found, removing from state", keyPath)
		d.SetId("")
		return nil
	}

	fields := []string{
		consts.FieldKeyName,
		consts.FieldKeyType,
		consts.FieldManagedKeyName,
		consts.FieldManagedKeyID,
	}

	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q for PKI Secret Key, err=%s",
				k, err)
		}
	}

	// key_bits not returned from Vault
	// set from config
	if err := d.Set(consts.FieldKeyBits, d.Get(consts.FieldKeyBits)); err != nil {
		return diag.Errorf("error setting state key %q for PKI Secret Key, err=%s",
			consts.FieldKeyBits, err)
	}

	return nil
}

func pkiSecretBackendKeyDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	keyPath := d.Id()

	log.Printf("[DEBUG] Deleting PKI Key at %q", keyPath)
	_, err := client.Logical().Delete(keyPath)
	if err != nil {
		return diag.Errorf("error deleting %q from Vault: %q", keyPath, err)
	}

	return nil
}

func pkiSecretMountFromPath(path string) (string, error) {
	if !pkiSecretMountFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no mount found")
	}
	res := pkiSecretMountFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for mount", len(res))
	}
	return res[1], nil
}

func pkiSecretKeyIDFromPath(path string) (string, error) {
	if !pkiSecretKeyIDFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no key ID found")
	}
	res := pkiSecretKeyIDFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for key ID", len(res))
	}
	return res[1], nil
}
