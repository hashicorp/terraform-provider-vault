// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func genericSecretItemDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(genericSecretItemDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Full path from which a secret will be read.",
			},

			consts.FieldKey: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the secret item to read.",
			},

			consts.FieldValue: {
				Type:        schema.TypeString,
				Required:    false,
				Computed:    true,
				Description: "Content of the secret item to read.",
				Sensitive:   true,
			},
		},
	}
}

func genericSecretItemDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get(consts.FieldPath).(string)
	key := d.Get(consts.FieldKey).(string)

	secret, err := versionedSecret(-1, path, client)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		return fmt.Errorf("no secret found at %q", path)
	}

	if _, ok := secret.Data[key]; !ok {
		return fmt.Errorf("no secret item named %q was found", key)
	}

	d.SetId(key)

	if err := d.Set(consts.FieldKey, key); err != nil {
		return err
	}

	if err := d.Set(consts.FieldValue, secret.Data[d.Get(consts.FieldKey).(string)]); err != nil {
		return err
	}

	return nil
}
