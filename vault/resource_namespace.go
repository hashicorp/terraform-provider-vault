// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func namespaceResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: namespaceCreate,
		UpdateContext: namespaceUpdate,
		DeleteContext: namespaceDelete,
		ReadContext:   provider.ReadContextWrapper(namespaceRead),
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
			consts.FieldCustomMetadata: {
				Type:     schema.TypeMap,
				Computed: true,
				Optional: true,
				Description: "Custom metadata describing this namespace. Value type " +
					"is map[string]string.",
			},
		},
	}
}

func namespaceCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)

	var data map[string]interface{}

	// data is non-nil only if Vault version >= 1.12
	// and custom_metadata is provided
	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		if v, ok := d.GetOk(consts.FieldCustomMetadata); ok {
			data = map[string]interface{}{
				consts.FieldCustomMetadata: v,
			}
		}
	}

	log.Printf("[DEBUG] Creating namespace %s in Vault", path)
	_, err := client.Logical().Write(consts.SysNamespaceRoot+path, data)
	if err != nil {
		return diag.Errorf("error writing to Vault: %s", err)
	}

	return namespaceRead(ctx, d, meta)
}

func namespaceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// Updating a namespace is only supported in
	// Vault versions >= 1.12
	if !provider.IsAPISupported(meta, provider.VaultVersion112) {
		return nil
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)

	var data map[string]interface{}
	if v, ok := d.GetOk(consts.FieldCustomMetadata); ok {
		data = map[string]interface{}{
			consts.FieldCustomMetadata: v,
		}
	}

	log.Printf("[DEBUG] Creating namespace %s in Vault", path)
	if _, err := client.Logical().JSONMergePatch(ctx, consts.SysNamespaceRoot+path, data); err != nil {
		return diag.Errorf("error writing to Vault: %s", err)
	}

	return namespaceRead(ctx, d, meta)
}

func namespaceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
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
		return diag.Errorf("error deleting from Vault: %s", err)
	}

	// wait for the namespace to be gone...
	return diag.FromErr(backoff.RetryNotify(func() error {
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
	))
}

func namespaceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	upgradeNonPathdNamespaceID(d)

	path := d.Id()

	resp, err := client.Logical().Read(consts.SysNamespaceRoot + path)
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}

	if resp == nil {
		log.Printf("[WARN] Names %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	d.SetId(resp.Data[consts.FieldPath].(string))

	toSet := map[string]interface{}{
		consts.FieldNamespaceID: resp.Data[consts.FieldID],
		consts.FieldPath:        mountutil.TrimSlashes(path),
		// set computed parameter to nil for vault versions <= 1.11
		// prevents 'known after apply' drift in TF state since field
		// would never be set otherwise
		consts.FieldCustomMetadata: nil,
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		toSet[consts.FieldCustomMetadata] = resp.Data[consts.FieldCustomMetadata]
	}

	pathFQ := path
	if parent, ok := d.GetOk(consts.FieldNamespace); ok {
		pathFQ = strings.Join([]string{parent.(string), path}, "/")
	}
	toSet[consts.FieldPathFQ] = pathFQ

	if err := util.SetResourceData(d, toSet); err != nil {
		return diag.FromErr(err)
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
