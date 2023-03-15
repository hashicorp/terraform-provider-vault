// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"golang.org/x/net/context"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var mongodbAtlasAPIFields = []string{
	"public_key",
	"private_key",
}

func mongodbAtlasSecretBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: mongodbAtlasSecretBackendCreate,
		ReadContext:   ReadContextWrapper(mongodbAtlasSecretBackendRead),
		UpdateContext: mongodbAtlasSecretBackendUpdate,
		DeleteContext: mongodbAtlasSecretBackendDelete,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where MongoDB Atlas secret backend will be mounted",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			"public_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The Public Programmatic API Key used to authenticate with the MongoDB Atlas API",
			},
			"private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The Private Programmatic API Key used to connect with MongoDB Atlas API",
			},
		},
	})
}

func mongodbAtlasSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Get("path").(string)

	data := make(map[string]interface{})
	if privateKey, ok := d.Get("private_key").(string); ok {
		data["private_key"] = privateKey
	}
	if publicKey, ok := d.Get("public_key").(string); ok {
		data["public_key"] = publicKey
	}

	log.Printf("[DEBUG] Mounting MongoDB Atlas backend at %q", path)
	_, err := client.Logical().Write(path+"/config", data)
	if err != nil {
		return diag.Errorf("error mounting to %q, err=%w", path, err)
	}

	log.Printf("[DEBUG] Mounted MongoDB Atlas backend at %q", path)
	d.SetId(path)

	return mongodbAtlasSecretBackendUpdate(ctx, d, meta)
}

func mongodbAtlasSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	if !d.IsNewResource() && d.HasChange("path") {
		src := path
		dest := d.Get("path").(string)

		log.Printf("[DEBUG] Remount %s to %s in Vault", src, dest)

		err := client.Sys().Remount(src, dest)
		if err != nil {
			return diag.Errorf("error remounting in Vault: %s", err)
		}

		// There is something similar in resource_mount.go, but in the call to TuneMount().
		var tries int
		for {
			if tries > 10 {
				return diag.Errorf(
					"mount %q did did not become available after %d tries, interval=1s", dest, tries)
			}

			enabled, err := util.CheckMountEnabled(client, dest)
			if err != nil {
				return diag.FromErr(err)
			}
			if !enabled {
				tries++
				time.Sleep(1 * time.Second)
				continue
			}

			break
		}

		path = dest
		d.SetId(path)
	}

	log.Printf("[DEBUG] Updating mount %s in Vault", path)

	data := map[string]interface{}{}
	configPath := fmt.Sprintf("%s/config", path)
	log.Printf("[DEBUG] Updating %q", configPath)

	for _, k := range mongodbAtlasAPIFields {
		if d.HasChange(k) {
			if v, ok := d.GetOk(k); ok {
				switch v.(type) {
				case *schema.Set:
					data[k] = util.TerraformSetToStringArray(v)
				default:
					data[k] = v
				}
			}
		}
	}

	if _, err := client.Logical().Write(configPath, data); err != nil {
		return diag.Errorf("error updating MongoDB Atlas config %q, err=%w", configPath, err)
	}

	log.Printf("[DEBUG] Updated %q", configPath)

	return mongodbAtlasSecretBackendRead(ctx, d, meta)
}

func mongodbAtlasSecretBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Reading MongoDB Atlas config at %s/config", path)
	resp, err := client.Logical().Read(path + "/config")
	if err != nil {
		return diag.Errorf("error reading MongoDB Atlas config at %q/config: err=%w", path, err)
	}

	if resp == nil {
		log.Printf("[WARN] MongoDB Atlas config not found, removing from state")
		d.SetId("")

		return nil
	}

	for _, k := range mongodbAtlasAPIFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q on MongoDB Atlas config, err=%w", k, err)
		}
	}

	return nil
}

func mongodbAtlasSecretBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()
	log.Printf("[DEBUG] Unmounting MongoDB Atlas backend %q", path)

	if err := client.Sys().Unmount(path); err != nil {
		if util.Is404(err) {
			log.Printf("[WARN] %q not found, removing from state", path)
			d.SetId("")

			return diag.Errorf("error unmounting MongoDB Atlas backend from %q, err=%w", path, err)
		}

		return diag.Errorf("error unmounting MongoDB Atlas backend from %q, err=%w", path, err)
	}

	log.Printf("[DEBUG] Unmounted MongoDB Atlas backend %q", path)

	return nil
}
