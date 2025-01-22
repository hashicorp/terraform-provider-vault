// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func genericSecretItemResource(name string) *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: genericSecretItemResourceWrite,
		Update: genericSecretItemResourceWrite,
		Delete: genericSecretItemResourceDelete,
		Read:   provider.ReadWrapper(genericSecretItemResourceRead),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		MigrateState: resourceGenericSecretMigrateState,

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where the generic secret will be written.",
			},

			"id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			consts.FieldKey: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the secret to write.",
			},

			consts.FieldValue: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Content of the secret to write.",
				Sensitive:   true,
			},
		},
	}
}

func genericSecretItemResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get(consts.FieldPath).(string)

	secret, err := versionedSecret(-1, path, client)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		return fmt.Errorf("no secret found at %q", path)
	}

	identifier := uuid.New().String()

	d.SetId(identifier)
	d.Set("id", identifier)

	return nil
}

func genericSecretItemResourceDelete(d *schema.ResourceData, meta interface{}) error {
	log.Println("genericSecretItemResourceDelete")
	return nil
}

func genericSecretItemResourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get(consts.FieldPath).(string)

	secret, err := versionedSecret(-1, path, client)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		return fmt.Errorf("no secret found at %q", path)
	}

	data := secret.Data
	jsonData, err := json.Marshal(secret.Data)
	if err != nil {
		return fmt.Errorf("error marshaling JSON for %q: %s", path, err)
	}

	fmt.Println("data--------------", data, jsonData)

	// if err := d.Set(consts.FieldDataJSON, string(jsonData)); err != nil {
	// 	return err
	// }
	// if err := d.Set(consts.FieldPath, path); err != nil {
	// 	return err
	// }

	// if err := d.Set("data", data); err != nil {
	// 	return err
	// }

	return nil
}
