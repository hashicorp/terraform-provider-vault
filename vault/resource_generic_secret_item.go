// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"sync"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var (
	genericSecretItemResourceWriteMutex  sync.Mutex
	genericSecretItemResourceDeleteMutex sync.Mutex
	genericSecretItemResourceReadMutex   sync.Mutex
)

func genericSecretItemResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: genericSecretItemResourceWrite,
		Update: genericSecretItemResourceWrite,
		Delete: genericSecretItemResourceDelete,
		Read:   provider.ReadWrapper(genericSecretItemResourceRead),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where the generic secret item will be written.",
			},

			consts.FieldKey: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the secret item to write.",
			},

			consts.FieldValue: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Content of the secret item to write.",
				Sensitive:   true,
			},
		},
	}
}

func genericSecretItemResourceWrite(d *schema.ResourceData, meta interface{}) error {
	genericSecretItemResourceWriteMutex.Lock()
	defer genericSecretItemResourceWriteMutex.Unlock()

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get(consts.FieldPath).(string)
	key := d.Get(consts.FieldKey).(string)

	d.SetId(key)

	secret, err := versionedSecret(-1, path, client)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	var shouldCreateSecret bool

	if secret == nil {
		shouldCreateSecret = true
		secret = &api.Secret{
			Data: map[string]interface{}{
				key: d.Get(consts.FieldValue).(string),
			},
		}
	}

	if !shouldCreateSecret {
		for k, v := range secret.Data {
			if k == key {
				if v == d.Get(consts.FieldValue).(string) {
					return nil
				}

				break
			}
		}

		secret.Data[key] = d.Get(consts.FieldValue).(string)
	}

	data := secret.Data

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return fmt.Errorf("error determining if it's a v2 path: %s", err)
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
		data = map[string]interface{}{
			"data":    data,
			"options": map[string]interface{}{},
		}
	}

	if _, err := util.RetryWrite(client, path, data, util.DefaultRequestOpts()); err != nil {
		return err
	}

	return genericSecretItemResourceRead(d, meta)
}

func genericSecretItemResourceDelete(d *schema.ResourceData, meta interface{}) error {
	genericSecretItemResourceDeleteMutex.Lock()
	defer genericSecretItemResourceDeleteMutex.Unlock()

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

	for k := range secret.Data {
		if k == key {
			delete(secret.Data, k)
			break
		}
	}

	data := secret.Data

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return fmt.Errorf("error determining if it's a v2 path: %s", err)
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
		data = map[string]interface{}{
			"data":    data,
			"options": map[string]interface{}{},
		}
	}

	if _, err := util.RetryWrite(client, path, data, util.DefaultRequestOpts()); err != nil {
		return err
	}

	return nil
}

func genericSecretItemResourceRead(d *schema.ResourceData, meta interface{}) error {
	genericSecretItemResourceReadMutex.Lock()
	defer genericSecretItemResourceReadMutex.Unlock()

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

	d.SetId(key)

	if err := d.Set(consts.FieldKey, key); err != nil {
		return err
	}

	if err := d.Set(consts.FieldValue, secret.Data[d.Get(consts.FieldKey).(string)]); err != nil {
		return err
	}

	return nil
}
