// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	syncutil "github.com/hashicorp/terraform-provider-vault/internal/sync"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

var syncAssociationFieldsFromIDRegex = regexp.MustCompile("^(.+)/dest/(.+)/mount/(.+)/secret/(.+)$")

const (
	fieldSecretName = "secret_name"
	fieldSyncStatus = "sync_status"
	fieldUpdatedAt  = "updated_at"
	fieldSubkeys    = "subkeys"
)

func secretsSyncAssociationResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(secretsSyncAssociationWrite, provider.VaultVersion116),
		ReadContext:   provider.ReadContextWrapper(secretsSyncAssociationRead),
		DeleteContext: secretsSyncAssociationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

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
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of sync status for each subkey of the associated secret.",
			},
			fieldUpdatedAt: {
				Type:     schema.TypeMap,
				Computed: true,
				Description: "Map of duration string stating when the secret was last updated for " +
					"each subkey of the secret.",
			},
			fieldSubkeys: {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed:    true,
				Description: "Subkeys for the associated secret.",
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
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error setting secrets sync association %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote association to %q", path)

	// ex: gh/dest/gh-dest-1/mount/kv/secret/token
	// unique. each destination should only have one association for a particular accessor and secret
	id := fmt.Sprintf("%s/dest/%s/mount/%s/secret/%s", destType, name, mount, secretName)
	d.SetId(id)

	return secretsSyncAssociationRead(ctx, d, meta)
}

func secretsSyncAssociationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()
	fields, err := syncAssociationFieldsFromID(id)
	if err != nil {
		return diag.FromErr(err)
	}

	typ := fields[0]
	destName := fields[1]
	mount := fields[2]
	secretName := fields[3]

	if err := d.Set(fieldSecretName, secretName); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldName, destName); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldType, typ); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldMount, mount); err != nil {
		return diag.FromErr(err)
	}

	accessor, err := getMountAccessor(ctx, d, meta, mount)
	if err != nil {
		return diag.Errorf("could not obtain accessor from given mount; err=%s", err)
	}
	// List all associations for secret destination
	resp, err := client.Logical().Read(fmt.Sprintf("%s/%s", syncutil.SecretsSyncDestinationPath(destName, typ), "associations"))
	if err != nil {
		return diag.Errorf("error reading associations for destination %s of type %s", destName, typ)
	}

	model, err := getSyncAssociationModelFromResponse(resp)
	if err != nil {
		return diag.FromErr(err)
	}

	status := map[string]string{}
	updatedAt := map[string]string{}
	subKeys := make([]string, 0)
	for k, v := range model.AssociatedSecrets {
		if v.SecretName == secretName && v.Accessor == accessor {
			status[k] = v.SyncStatus
			updatedAt[k] = v.UpdatedAt
			// only add sub-keys if they are non-zero
			if v.Subkey != "" {
				subKeys = append(subKeys, v.Subkey)
			}
		}
	}

	if len(status) == 0 {
		return diag.Errorf("no associated secrets found for given mount accessor and secret name %s/%s", accessor, secretName)
	}

	if err := d.Set(fieldSyncStatus, status); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(fieldSubkeys, subKeys); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(fieldUpdatedAt, updatedAt); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func secretsSyncAssociationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()
	fields, err := syncAssociationFieldsFromID(id)
	if err != nil {
		return diag.FromErr(err)
	}

	destType := fields[0]
	destName := fields[1]
	mount := fields[2]
	secretName := fields[3]

	path := secretsSyncAssociationDeletePath(destName, destType)

	data := map[string]interface{}{
		fieldSecretName:   secretName,
		consts.FieldMount: mount,
	}

	log.Printf("[DEBUG] Removing association from %q", path)
	_, err = client.Logical().Write(path, data)
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

func getMountAccessor(ctx context.Context, d *schema.ResourceData, meta interface{}, mount string) (string, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return "", e
	}

	log.Printf("[DEBUG] Reading mount %s from Vault", mount)

	m, err := mountutil.GetMount(ctx, client, mount)
	if errors.Is(err, mountutil.ErrMountNotFound) {
		return "", fmt.Errorf("expected mount at %s; no mount found", mount)
	}

	if err != nil {
		return "", err
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
	Subkey     string `json:"sub_key"`
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

func syncAssociationFieldsFromID(id string) ([]string, error) {
	if !syncAssociationFieldsFromIDRegex.MatchString(id) {
		return nil, fmt.Errorf("regex did not match")
	}
	res := syncAssociationFieldsFromIDRegex.FindStringSubmatch(id)
	// 5 matches
	// full string itself
	// 4 desired fields
	if len(res) != 5 {
		return nil, fmt.Errorf("unexpected number of matches (%d) for fields; "+""+
			"format=:type/dest/:destination/mount/:mount/secret/:secretName", len(res))
	}
	return res[1:], nil
}
