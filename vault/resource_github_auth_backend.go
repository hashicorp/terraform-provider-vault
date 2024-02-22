// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func githubAuthBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldPath: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Path where the auth backend is mounted",
			Default:     consts.MountTypeGitHub,
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"organization": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The organization users must be part of.",
		},
		"organization_id": {
			Type:     schema.TypeInt,
			Optional: true,
			Computed: true,
			Description: "The ID of the organization users must be part of. " +
				"Vault will attempt to fetch and set this value if it is not provided (vault-1.10+)",
		},
		"base_url": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "The API endpoint to use. Useful if you are running GitHub Enterprise or an API-compatible authentication server.",
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Specifies the description of the mount. This overrides the current stored value, if any.",
		},
		"accessor": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "The mount accessor related to the auth mount.",
		},
		"tune": authMountTuneSchema(),
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return provider.MustAddMountMigrationSchema(&schema.Resource{
		Create: githubAuthBackendCreate,
		Read:   provider.ReadWrapper(githubAuthBackendRead),
		Update: githubAuthBackendUpdate,
		Delete: githubAuthBackendDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema:        fields,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
	}, false)
}

func githubAuthBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	var description string

	path := strings.Trim(d.Get(consts.FieldPath).(string), "/")

	if v, ok := d.GetOk("description"); ok {
		description = v.(string)
	}

	log.Printf("[DEBUG] Enabling github auth backend at '%s'", path)
	err := client.Sys().EnableAuthWithOptions(path, &api.EnableAuthOptions{
		Type:        consts.MountTypeGitHub,
		Description: description,
	})
	if err != nil {
		return fmt.Errorf("error enabling github auth backend at '%s': %s", path, err)
	}
	log.Printf("[INFO] Enabled github auth backend at '%s'", path)

	d.SetId(path)
	d.MarkNewResource()
	d.Partial(true)
	return githubAuthBackendUpdate(d, meta)
}

func githubAuthBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := "auth/" + d.Id()
	configPath := path + "/config"

	if !d.IsNewResource() {
		mount, err := util.Remount(d, client, consts.FieldPath, true)
		if err != nil {
			return err
		}

		path = "auth/" + mount
		configPath = path + "/config"
	}

	data := map[string]interface{}{}

	if v, ok := d.GetOk("organization"); ok {
		data["organization"] = v.(string)
	}
	if v, ok := d.GetOk("organization_id"); ok {
		data["organization_id"] = v.(int)
	}
	if v, ok := d.GetOk("base_url"); ok {
		data["base_url"] = v.(string)
	}

	updateTokenFields(d, data, false)

	log.Printf("[DEBUG] Writing github auth config to '%q'", configPath)
	_, err := client.Logical().Write(configPath, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("error writing github config to '%q': %s", configPath, err)
	}
	log.Printf("[INFO] Github auth config successfully written to '%q'", configPath)

	if d.HasChange("tune") {
		log.Printf("[INFO] Github Auth '%q' tune configuration changed", d.Id())
		if raw, ok := d.GetOk("tune"); ok {
			log.Printf("[DEBUG] Writing github auth tune to '%q'", path)

			err := authMountTune(client, path, raw)
			if err != nil {
				return nil
			}

			log.Printf("[INFO] Written github auth tune to '%q'", path)
		}
	}

	if d.HasChange("description") {
		description := d.Get("description").(string)
		tune := api.MountConfigInput{Description: &description}
		err := client.Sys().TuneMount(path, tune)
		if err != nil {
			log.Printf("[ERROR] Error updating github auth description to '%q'", path)
			return err
		}
	}

	d.Partial(false)
	return githubAuthBackendRead(d, meta)
}

func githubAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := "auth/" + d.Id()
	configPath := path + "/config"

	log.Printf("[DEBUG] Reading github auth mount from '%q'", path)
	mount, err := mountutil.GetAuthMount(context.Background(), client, path)
	if errors.Is(err, mountutil.ErrMountNotFound) {
		log.Printf("[WARN] Mount %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	log.Printf("[INFO] Read github auth mount from '%q'", path)

	log.Printf("[DEBUG] Reading github auth config from '%q'", configPath)
	resp, err := client.Logical().Read(configPath)
	if err != nil {
		return fmt.Errorf("error reading github auth config from '%q': %w", configPath, err)
	}
	log.Printf("[INFO] Read github auth config from '%q'", configPath)

	if resp == nil {
		log.Printf("[WARN] Github auth config from '%q' not found, removing from state", configPath)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Reading github auth tune from '%q/tune'", path)
	rawTune, err := authMountTuneGet(client, path)
	if err != nil {
		return fmt.Errorf("error reading tune information from Vault: %w", err)
	}

	data := getCommonTokenFieldMap(resp)
	data["path"] = d.Id()
	data["organization"] = resp.Data["organization"]
	data["base_url"] = resp.Data["base_url"]
	data["description"] = mount.Description
	data["accessor"] = mount.Accessor
	data["tune"] = []map[string]interface{}{rawTune}

	if orgID, ok := resp.Data["organization_id"]; ok {
		data["organization_id"] = orgID
	}

	if err := util.SetResourceData(d, data); err != nil {
		return err
	}

	return nil
}

func githubAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	return authMountDisable(client, d.Id())
}
