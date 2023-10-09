// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func AuthBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		SchemaVersion: 1,

		Create: authBackendWrite,
		Delete: authBackendDelete,
		Read:   provider.ReadWrapper(authBackendRead),
		Update: authBackendUpdate,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		MigrateState:  resourceAuthBackendMigrateState,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),

		Schema: map[string]*schema.Schema{
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the auth backend",
			},

			consts.FieldPath: {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  "path to mount the backend. This defaults to the type.",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},

			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"local": {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Description: "Specifies if the auth method is local only",
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the auth backend",
			},

			"tune": authMountTuneSchema(),
		},
	}, false)
}

func authBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	mountType := d.Get("type").(string)
	path := d.Get(consts.FieldPath).(string)

	if path == "" {
		path = mountType
	}

	options := &api.EnableAuthOptions{
		Type:        mountType,
		Description: d.Get("description").(string),
		Local:       d.Get("local").(bool),
	}

	log.Printf("[DEBUG] Writing auth %q to Vault", path)
	if err := client.Sys().EnableAuthWithOptions(path, options); err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return authBackendUpdate(d, meta)
}

func authBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting auth %s from Vault", path)

	if err := client.Sys().DisableAuth(path); err != nil {
		return fmt.Errorf("error disabling auth from Vault: %s", err)
	}

	return nil
}

func authBackendRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	mount, err := getAuthMountIfPresent(client, path)
	if err != nil {
		return err
	}

	if mount == nil {
		d.SetId("")
		return nil
	}

	if err := d.Set("type", mount.Type); err != nil {
		return err
	}
	if err := d.Set(consts.FieldPath, path); err != nil {
		return err
	}
	if err := d.Set("description", mount.Description); err != nil {
		return err
	}
	if err := d.Set("local", mount.Local); err != nil {
		return err
	}
	if err := d.Set("accessor", mount.Accessor); err != nil {
		return err
	}

	return nil
}

func authBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Updating auth %s in Vault", path)

	if !d.IsNewResource() {
		path, e = util.Remount(d, client, consts.FieldPath, true)
		if e != nil {
			return e
		}
	}

	backendType := d.Get("type").(string)
	var input api.MountConfigInput
	var callTune bool

	if d.HasChange("tune") {
		log.Printf("[INFO] Auth '%q' tune configuration changed", path)

		if raw, ok := d.GetOk("tune"); ok {
			log.Printf("[DEBUG] Writing %s auth tune to '%q'", backendType, path)

			input = expandAuthMethodTune(raw.(*schema.Set).List())
		}
		callTune = true
	}

	if d.HasChange("description") && !d.IsNewResource() {
		desc := d.Get("description").(string)
		input.Description = &desc
		callTune = true
	}

	if callTune {
		if err := tuneMount(client, "auth/"+path, input); err != nil {
			return err
		}

		log.Printf("[INFO] Written %s auth tune to '%q'", backendType, path)
	}

	return authBackendRead(d, meta)
}
