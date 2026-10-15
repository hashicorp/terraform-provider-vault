// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func transitSecretBackendKeyVersionDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(transitSecretBackendKeyVersionDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Transit secret backend the key belongs to.",
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the key to read.",
			},
			consts.FieldVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Computed:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Description:  "The version of the key to read. If unset or 0, the latest version is read.",
			},
			consts.FieldType: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The type of this key version.",
			},
			consts.FieldPublicKey: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The public key of this key version, for asymmetric key types.",
			},
			consts.FieldParameterSet: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The parameter set of this key version, for ML-DSA, SLH-DSA and hybrid keys.",
			},
			consts.FieldHybridKeyTypeEC: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The elliptic curve algorithm of this key version, for hybrid keys.",
			},
			consts.FieldHybridKeyTypePQC: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The post-quantum algorithm of this key version, for hybrid keys.",
			},
			consts.FieldSupportsEncryption: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not this key version supports encryption, based on key type.",
			},
			consts.FieldSupportsDecryption: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not this key version supports decryption, based on key type.",
			},
			consts.FieldSupportsDerivation: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not this key version supports derivation, based on key type.",
			},
			consts.FieldSupportsSigning: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not this key version supports signing, based on key type.",
			},
		},
	}
}

func transitSecretBackendKeyVersionDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	if !transitCryptoAgilitySupported(meta) {
		return fmt.Errorf("reading a key version requires Vault Enterprise 2.2.0 or later")
	}

	backend := d.Get(consts.FieldBackend).(string)
	name := d.Get(consts.FieldName).(string)
	version := d.Get(consts.FieldVersion).(int)

	// The server reads the latest version when the version is 0.
	path := fmt.Sprintf("%s/versions/%d", transitSecretBackendKeyPath(backend, name), version)

	log.Printf("[DEBUG] Reading transit key version from %q", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading transit key version %q: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return fmt.Errorf("no transit key version found at %q", path)
	}

	d.SetId(path)

	fields := []string{
		consts.FieldVersion, consts.FieldType, consts.FieldPublicKey,
		consts.FieldParameterSet, consts.FieldHybridKeyTypeEC, consts.FieldHybridKeyTypePQC,
		consts.FieldSupportsEncryption, consts.FieldSupportsDecryption,
		consts.FieldSupportsDerivation, consts.FieldSupportsSigning,
	}
	for _, f := range fields {
		if v, ok := secret.Data[f]; ok {
			if err := d.Set(f, v); err != nil {
				return fmt.Errorf("error setting state key %q: %w", f, err)
			}
		}
	}

	return nil
}
