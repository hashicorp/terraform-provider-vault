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

func pkiSecretBackendConfigScepResource() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages Vault PKI SCEP configuration",
		CreateContext: provider.MountCreateContextWrapper(pkiSecretBackendConfigScepWrite, provider.VaultVersion116),
		UpdateContext: pkiSecretBackendConfigScepWrite,
		ReadContext:   pkiSecretBackendConfigScepRead,
		DeleteContext: pkiSecretBackendConfigScepDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: pkiSecretBackendConfigScepSchema(),
	}
}

func pkiSecretBackendConfigScepWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := verifyPkiScepFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := pkiSecretBackendConfigScepPath(backend)

	fieldsToSet := []string{
		consts.FieldEnabled,
		consts.FieldDefaultMount,
		consts.FieldDefaultPathPolicy,
		consts.FieldAllowedEncryptionAlgorithms,
		consts.FieldAllowedDigestAlgorithms,
	}

	data := map[string]interface{}{}
	for _, field := range fieldsToSet {
		if val, ok := d.GetOk(field); ok {
			data[field] = val
		}
	}

	if authenticatorsRaw, ok := d.GetOk(consts.FieldAuthenticators); ok {
		authenticators := authenticatorsRaw.([]interface{})
		var authenticator interface{}
		if len(authenticators) > 0 {
			authenticator = authenticators[0]
		}

		data[consts.FieldAuthenticators] = authenticator
	}

	log.Printf("[DEBUG] Updating SCEP config on PKI secret backend %q:\n%v", backend, data)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error updating SCEP config for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Updated SCEP config on PKI secret backend %q", backend)

	d.SetId(path)

	return pkiSecretBackendConfigScepRead(ctx, d, meta)
}

func pkiSecretBackendConfigScepRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	id := d.Id()
	if id == "" {
		return diag.FromErr(fmt.Errorf("no path set for import, id=%q", id))
	}

	backend := strings.TrimSuffix(id, "/config/scep")
	if err := d.Set("backend", backend); err != nil {
		return diag.FromErr(fmt.Errorf("failed setting field [%s] with value [%v]: %w", "backend", backend, err))
	}

	if err := verifyPkiScepFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed getting client: %w", err))
	}

	if err := readScepConfig(ctx, d, client, id); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func pkiSecretBackendConfigScepDelete(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	// There isn't any delete API for the SCEP config.
	return nil
}
