// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var requiredEabDataKeys = []string{"id", "key_type", "acme_directory", "key"}

/*
ACME EAB (External Account Binding) tokens, that restrict ACME accounts from
being created anonymously
*/
func pkiSecretBackendAcmeEabResource() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages Vault PKI ACME EAB bindings",
		CreateContext: provider.MountCreateContextWrapper(pkiSecretBackendCreateAcmeEab, provider.VaultVersion114),
		ReadContext:   pkiSecretBackendReadAcmeEab,
		DeleteContext: pkiSecretBackendDeleteAcmeEab,
		// There is no UpdateContext or ImportContext for EAB tokens as there is no read API available

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to",
				ForceNew:    true,
			},
			consts.FieldIssuer: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the issuer reference to use for directory path",
				ForceNew:    true, // If this is changed/set a new directory path will need to be calculated
			},
			consts.FieldRole: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the role to use for directory path",
				ForceNew:    true, // If this is changed/set a new directory path will need to be calculated
			},
			// Response fields for EAB
			consts.FieldEabId: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The identifier of a specific ACME EAB token",
			},
			consts.FieldKeyType: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The key type of the EAB key",
			},
			consts.FieldAcmeDirectory: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The ACME directory to which the key belongs",
			},
			consts.FieldEabKey: {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The ACME EAB token",
			},
			consts.FieldsCreatedOn: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "An RFC3339 formatted date time when the EAB token was created",
			},
		},
	}
}

func pkiSecretBackendCreateAcmeEab(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return pkiSecretBackendReadAcmeEab(ctx, d, meta)
}

func pkiSecretBackendReadAcmeEab(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	var issuer, role string
	// These are optional inputs that will determine our path to use to create the EAB token
	if issuerVal, ok := d.GetOk(consts.FieldIssuer); ok {
		issuer = issuerVal.(string)
	}
	if roleVal, ok := d.GetOk(consts.FieldRole); ok {
		role = roleVal.(string)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := pkiSecretBackendComputeAcmeDirectoryPath(backend, issuer, role)

	log.Printf("[DEBUG] Creating new ACME EAB token on PKI secret backend %q at path: %q", backend, path)
	secret, err := client.Logical().WriteWithContext(ctx, path, map[string]interface{}{})
	if err != nil || secret == nil {
		return diag.Errorf("error creating new ACME EAB on PKI secret backend %q at path %q: %s", backend, path, err)
	}

	for _, reqKey := range requiredEabDataKeys {
		if rawVal, ok := secret.Data[reqKey]; !ok {
			return diag.Errorf("eab response missing required field: %q", reqKey)
		} else {
			if val, ok := rawVal.(string); !ok {
				return diag.Errorf("eab response field: %q was not a string", reqKey)
			} else if len(val) == 0 {
				return diag.Errorf("eab response has empty required field: %q", reqKey)
			}
		}
	}

	log.Printf("[DEBUG] Successfully created new ACME EAB token on backend %q at path %q", backend, path)
	eabId := secret.Data["id"].(string)
	fieldsToSet := map[string]string{
		consts.FieldEabId:         eabId,
		consts.FieldKeyType:       secret.Data["key_type"].(string),
		consts.FieldAcmeDirectory: secret.Data["acme_directory"].(string),
		consts.FieldEabKey:        secret.Data["key"].(string),
		consts.FieldsCreatedOn:    secret.Data["created_on"].(string),
	}

	d.SetId(fmt.Sprintf("acme-eab:%s:%s", path, eabId))
	for key, val := range fieldsToSet {
		if err := d.Set(key, val); err != nil {
			return diag.FromErr(fmt.Errorf("failed setting field %q: %w", key, err))
		}
	}

	return nil
}

func pkiSecretBackendDeleteAcmeEab(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(data, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := data.Get(consts.FieldBackend).(string)
	eabId := data.Get(consts.FieldEabId).(string)
	acmeDirectory := data.Get(consts.FieldAcmeDirectory).(string)

	log.Printf("[DEBUG] Deleting EAB token %q under path %q if unused", eabId, acmeDirectory)
	path := pkiSecretBackendComputeAcmeEabPath(backend, eabId)
	resp, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(err)
	}
	_ = resp
	log.Printf("[DEBUG] Deleted EAB token %q if it was unused", eabId)
	return nil
}

func pkiSecretBackendComputeAcmeEabPath(backend, eabId string) string {
	trimmedBackend := strings.TrimPrefix(strings.TrimSpace(backend), "/")
	trimmedEabId := strings.TrimSpace(eabId)
	return fmt.Sprintf("%s/eab/%s", trimmedBackend, trimmedEabId)
}

func pkiSecretBackendComputeAcmeDirectoryPath(backend string, issuer string, role string) string {
	trimmedBackend := strings.TrimPrefix(strings.TrimSpace(backend), "/")
	trimmedIssuer := strings.TrimSpace(issuer)
	trimmedRole := strings.TrimSpace(role)

	switch {
	case len(trimmedIssuer) > 0 && len(trimmedRole) > 0:
		return fmt.Sprintf("%s/issuer/%s/roles/%s/acme/new-eab", trimmedBackend, trimmedIssuer, trimmedRole)
	case len(trimmedIssuer) > 0:
		return fmt.Sprintf("%s/issuer/%s/acme/new-eab", trimmedBackend, trimmedIssuer)
	case len(trimmedRole) > 0:
		return fmt.Sprintf("%s/roles/%s/acme/new-eab", trimmedBackend, trimmedRole)
	default:
		return fmt.Sprintf("%s/acme/new-eab", trimmedBackend)
	}
}
