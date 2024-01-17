// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldSecretName = "secret_name"
	fieldSyncStatus = "sync_status"
	fieldUpdatedAt  = "updated_at"
)

func secretsSyncAssociationResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(secretsSyncAssociationWrite, provider.VaultVersion116),
		ReadContext:   provider.ReadContextWrapper(secretsSyncAssociationRead),
		DeleteContext: secretsSyncAssociationDelete,

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the destination.",
				ForceNew:    true,
			},
			consts.FieldType: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Type of sync destination.",
				ForceNew:    true,
			},
			consts.FieldMount: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Specifies the mount where the secret is located.",
			},
			fieldSecretName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Specifies the name of the secret to synchronize.",
			},
			fieldSyncStatus: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Specifies the status of the association.",
			},
			fieldUpdatedAt: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Duration string stating when the secret was last updated.",
			},
		},
	}
}

func secretsSyncAssociationWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	destType := d.Get(consts.FieldType).(string)
	secretName := d.Get(fieldSecretName).(string)
	mount := d.Get(consts.FieldMount).(string)

	path := secretsSyncAssociationSetPath(name, destType)

	data := map[string]interface{}{
		fieldSecretName:   secretName,
		consts.FieldMount: mount,
	}

	log.Printf("[DEBUG] Writing association to %q", path)
	resp, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error setting secrets sync association %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote association to %q", path)

	// expect accessor to be provided from mount
	accessor, err := getMountAccessor(ctx, d, meta)
	if err != nil {
		return diag.Errorf("could not obtain accessor from given mount; err=%s", err)
	}
	vaultRespKey := fmt.Sprintf("%s/%s", accessor, secretName)

	saModel, err := getSyncAssociationModelFromResponse(resp)
	if err != nil {
		return diag.FromErr(err)
	}

	syncData, ok := saModel.AssociatedSecrets[vaultRespKey]
	if !ok {
		return diag.Errorf("no associated secrets found for given mount accessor and secret name %s", vaultRespKey)
	}

	// set data that is received from Vault upon writes to avoid extra sync association reads
	if err := d.Set(fieldSecretName, syncData.SecretName); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(fieldSyncStatus, syncData.SyncStatus); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(fieldUpdatedAt, syncData.UpdatedAt); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(path)

	return nil
}

func secretsSyncAssociationRead(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	return nil
}

func secretsSyncAssociationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	destType := d.Get(consts.FieldType).(string)
	path := secretsSyncAssociationDeletePath(name, destType)

	data := map[string]interface{}{}

	for _, k := range []string{
		fieldSecretName,
		consts.FieldMount,
	} {
		data[k] = d.Get(k)
	}

	log.Printf("[DEBUG] Removing association from %q", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error removing secrets sync association %q: %s", path, err)
	}
	log.Printf("[DEBUG] Removed association from %q", path)

	return nil
}

func secretsSyncAssociationSetPath(name, destType string) string {
	return fmt.Sprintf("sys/sync/destinations/%s/%s/associations/set", destType, name)
}

func secretsSyncAssociationDeletePath(name, destType string) string {
	return fmt.Sprintf("sys/sync/destinations/%s/%s/associations/remove", destType, name)
}

func getMountAccessor(ctx context.Context, d *schema.ResourceData, meta interface{}) (string, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return "", e
	}

	mount := d.Get(consts.FieldMount).(string)

	log.Printf("[DEBUG] Reading mount %s from Vault", mount)
	mounts, err := client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return "", err
	}

	// path can have a trailing slash, but doesn't need to have one
	// this standardises on having a trailing slash, which is how the
	// API always responds.
	m, ok := mounts[strings.Trim(mount, "/")+"/"]
	if !ok {
		return "", fmt.Errorf("expected mount at %s; no mount found", mount)
	}

	return m.Accessor, nil
}

type syncAssociationModel struct {
	AssociatedSecrets map[string]syncAssociationData `json:"associated_secrets"`
}

type syncAssociationData struct {
	Accessor   string `json:"accessor"`
	SecretName string `json:"secret_name"`
	SyncStatus string `json:"sync_status"`
	UpdatedAt  string `json:"updated_at"`
}

func getSyncAssociationModelFromResponse(resp *api.Secret) (*syncAssociationModel, error) {
	// convert resp data to JSON
	b, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("error converting vault response to JSON; err=%s", err)
	}

	// convert JSON to struct
	var model *syncAssociationModel
	err = json.Unmarshal(b, &model)
	if err != nil {
		return nil, fmt.Errorf("error converting JSON to sync association model; err=%s", err)
	}

	return model, nil
}
