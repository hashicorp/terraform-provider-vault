// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func transitSecretBackendKeyDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(readTransitSecretBackendKey),
		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where transit backend is mounted.",
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the key.",
			},
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Specifies the type of the key.",
			},
			"deletion_allowed": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Specifies if the key is allowed to be deleted.",
			},
			"derived": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Specifies if key derivation is used.",
			},
			"exportable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Speficies if keys is exportable.",
			},
			"allow_plaintext_backup": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Specifies if taking backup of named key in the plaintext format is enabled.",
			},
			"keys": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of key versions in the keyring with the corresponding creation time, name and public key.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"creation_time": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"public_key": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"certificate_chain": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			"min_decryption_version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Minimum key version to use for decryption.",
			},
			"min_encryption_version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Minimum key version to use for encryption.",
			},
			"supports_encryption": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports encryption, based on key type.",
			},
			"supports_decryption": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports decryption, based on key type.",
			},
			"supports_derivation": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports derivation, based on key type.",
			},
			"supports_signing": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports signing, based on key type.",
			},
			"imported": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Specifies if the key is imported.",
			},
		},
	}
}

func readTransitSecretBackendKey(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	keyName := d.Get(consts.FieldName).(string)
	path := fmt.Sprintf("%s/keys/%s", backend, keyName)

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", path)
	if resp == nil {
		return diag.FromErr(fmt.Errorf("no key found at %q", path))
	}

	d.SetId(path)

	keyComputedFields := []string{
		"type",
		"deletion_allowed",
		"derived",
		"exportable",
		"allow_plaintext_backup",
		"min_decryption_version",
		"min_encryption_version",
		"supports_encryption",
		"supports_decryption",
		"supports_derivation",
		"supports_signing",
		"imported",
	}

	for _, k := range keyComputedFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	var keys []interface{}
	for _, keyData := range resp.Data["keys"].(map[string]interface{}) {
		keyMap := keyData.(map[string]interface{})
		keys = append(keys, keyMap)
	}

	if err := d.Set("keys", keys); err != nil {
		return diag.FromErr(err)
	}

	return nil
}
