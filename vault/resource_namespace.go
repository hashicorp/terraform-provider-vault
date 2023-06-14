// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func namespaceResource() *schema.Resource {
	return &schema.Resource{
		Create: namespaceCreate,
		Update: namespaceCreate,
		Delete: namespaceDelete,
		Read:   provider.ReadWrapper(namespaceRead),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				Description:  "Namespace path.",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			consts.FieldNamespaceID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Namespace ID.",
			},
			consts.FieldPathFQ: {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "The fully qualified namespace path.",
			},
		},
	}
}

func namespaceCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get(consts.FieldPath).(string)

	log.Printf("[DEBUG] Creating namespace %s in Vault", path)
	_, err := client.Logical().Write(consts.SysNamespaceRoot+path, nil)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	return namespaceRead(d, meta)
}

func namespaceDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get(consts.FieldPath).(string)

	log.Printf("[DEBUG] Deleting namespace %s from Vault", path)

	deleteNS := func() error {
		if _, err := client.Logical().Delete(consts.SysNamespaceRoot + path); err != nil {
			// child namespaces exist under path "test-namespace-2161440981046539760/", cannot remove
			if respErr, ok := err.(*api.ResponseError); ok && (respErr.StatusCode == http.StatusBadRequest) {
				return err
			} else {
				return backoff.Permanent(err)
			}
		}

		return nil
	}

	// on vault-1.10+ the deletion of namespaces seems to be asynchronous which can lead to errors like:
	// child namespaces exist under path "test-namespace-2161440981046539760/", cannot remove'
	// we can retry the deletion in this case
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10)
	if err := backoff.RetryNotify(deleteNS, bo, func(err error, duration time.Duration) {
		log.Printf("[WARN] Deleting namespace %q failed, retrying in %s", path, duration)
	}); err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	// wait for the namespace to be gone...
	return backoff.RetryNotify(func() error {
		if resp, _ := client.Logical().Read(consts.SysNamespaceRoot + path); resp != nil {
			return fmt.Errorf("namespace %q still exists", path)
		}
		return nil
	},
		bo,
		func(err error, duration time.Duration) {
			log.Printf(
				"[WARN] Waiting for Vault to garbage collect the %q namespace, retrying in %s",
				path, duration)
		},
	)
}

func namespaceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	upgradeNonPathdNamespaceID(d)

	path := d.Id()

	resp, err := client.Logical().Read(consts.SysNamespaceRoot + path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	if resp == nil {
		log.Printf("[WARN] Names %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	d.SetId(resp.Data[consts.FieldPath].(string))

	toSet := map[string]interface{}{
		consts.FieldNamespaceID: resp.Data["id"],
		consts.FieldPath:        util.TrimSlashes(path),
	}

	pathFQ := path
	if parent, ok := d.GetOk(consts.FieldNamespace); ok {
		pathFQ = strings.Join([]string{parent.(string), path}, "/")
	}
	toSet[consts.FieldPathFQ] = pathFQ

	if err := util.SetResourceData(d, toSet); err != nil {
		return err
	}

	return nil
}

func upgradeNonPathdNamespaceID(d *schema.ResourceData) {
	// Upgrade ID to path
	id := d.Id()
	oldID := d.Id()
	path, ok := d.GetOk(consts.FieldPath)
	if id != path && ok {
		log.Printf("[DEBUG] Upgrading old ID to path - %s to %s", id, path)
		d.SetId(path.(string))
		log.Printf("[DEBUG] Setting namespace_id to old ID - %s", oldID)
		d.Set(consts.FieldNamespaceID, oldID)
	}
}
