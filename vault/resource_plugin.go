// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	fieldSHA256   = "sha256"
	fieldCommand  = "command"
	fieldArgs     = "args"
	fieldEnv      = "env"
	fieldOCIImage = "oci_image"
	fieldRuntime  = "runtime"
)

func pluginResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(pluginWrite, provider.VaultVersion116),
		ReadContext:   provider.ReadContextWrapper(pluginRead),
		DeleteContext: pluginDelete,

		Schema: map[string]*schema.Schema{
			consts.FieldType: {
				Type:        schema.TypeString,
				Description: `Type of plugin; one of "auth", "secret", or "database".`,
				Required:    true,
				ForceNew:    true,
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Description: "Name of the plugin.",
				Required:    true,
				ForceNew:    true,
			},
			consts.FieldVersion: {
				Type:        schema.TypeString,
				Description: "Semantic version of the plugin.",
				Optional:    true,
				ForceNew:    true,
			},
			fieldSHA256: {
				Type:        schema.TypeString,
				Description: "The SHA256 sum of the plugin binary.",
				Required:    true,
				ForceNew:    true,
			},
			fieldCommand: {
				Type:        schema.TypeString,
				Description: "The command to execute the plugin, relative to the plugin_directory.",
				Required:    true,
				ForceNew:    true,
			},
			fieldArgs: {
				Type:        schema.TypeList,
				Description: "Any additional arguments to pass to the plugin.",
				Optional:    true,
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			fieldEnv: {
				Type:        schema.TypeList,
				Description: "Any additional environment variables to run the plugin with.",
				Optional:    true,
				ForceNew:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			fieldOCIImage: {
				Type:        schema.TypeString,
				Description: "Specifies OCI image to run. If specified, setting command, args, and env will update the container's entrypoint, args, and environment variables (append-only) respectively.",
				Optional:    true,
				ForceNew:    true,
			},
			fieldRuntime: {
				Type:        schema.TypeString,
				Description: "Specifies Vault plugin runtime to use if oci_image is specified.",
				Optional:    true,
				ForceNew:    true,
			},
		},
	}
}

func pluginWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	pluginType, err := api.ParsePluginType(d.Get(consts.FieldType).(string))
	if err != nil {
		return diag.FromErr(err)
	}
	name := d.Get(consts.FieldName).(string)
	version := d.Get(consts.FieldVersion).(string)
	id := fmt.Sprintf("%s/%s", pluginType, name)
	if version != "" {
		id = fmt.Sprintf("%s/%s", id, version)
	}

	log.Printf("[DEBUG] Writing plugin %q", id)
	err = client.Sys().RegisterPluginWithContext(ctx, &api.RegisterPluginInput{
		Type:     pluginType,
		Name:     name,
		Version:  version,
		SHA256:   d.Get(fieldSHA256).(string),
		Command:  d.Get(fieldCommand).(string),
		Args:     util.ToStringArray(d.Get(fieldArgs).([]interface{})),
		Env:      util.ToStringArray(d.Get(fieldEnv).([]interface{})),
		OCIImage: d.Get(fieldOCIImage).(string),
		Runtime:  d.Get(fieldRuntime).(string),
	})
	if err != nil {
		return diag.Errorf("error updating plugin %q: %s", id, err)
	}
	log.Printf("[DEBUG] Wrote plugin %q", id)

	d.SetId(id)

	return nil
}

func pluginRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	pluginType, err := api.ParsePluginType(d.Get(consts.FieldType).(string))
	if err != nil {
		return diag.FromErr(err)
	}
	name := d.Get(consts.FieldName).(string)
	version := d.Get(consts.FieldVersion).(string)

	resp, err := client.Sys().GetPluginWithContext(ctx, &api.GetPluginInput{
		Type:    pluginType,
		Name:    name,
		Version: version,
	})

	if err != nil {
		return diag.Errorf("error reading plugin %q %q %q: %s", pluginType, name, version, err)
	}

	d.Set(fieldSHA256, resp.SHA256)
	d.Set(fieldCommand, resp.Command)
	d.Set(fieldArgs, resp.Args)
	d.Set(fieldOCIImage, resp.OCIImage)
	d.Set(fieldRuntime, resp.Runtime)

	return nil
}

func pluginDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	pluginType, err := api.ParsePluginType(d.Get(consts.FieldType).(string))
	if err != nil {
		return diag.FromErr(err)
	}
	name := d.Get(consts.FieldName).(string)
	version := d.Get(consts.FieldVersion).(string)

	log.Printf("[DEBUG] Removing plugin %q %q %q", pluginType, name, version)
	err = client.Sys().DeregisterPluginWithContext(ctx, &api.DeregisterPluginInput{
		Type:    pluginType,
		Name:    name,
		Version: version,
	})
	if err != nil {
		return diag.Errorf("error removing plugin %q %q %q: %s", pluginType, name, version, err)
	}
	log.Printf("[DEBUG] Removed plugin %q %q %q", pluginType, name, version)

	return nil
}
