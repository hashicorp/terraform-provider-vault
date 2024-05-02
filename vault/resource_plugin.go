// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/go-version"
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

var (
	// Version regex is intentionally loose, its main purpose is to disallow
	// slashes so they can be used to delineate from the name. Version segment
	// is optional.
	pluginIDRegex = regexp.MustCompile(`^(auth|secret|database)(?:/version/([0-9a-zA-Z.-]+?))?/name/(.+)$`)
)

func pluginFromID(id string) (typ string, name string, version string) {
	matches := pluginIDRegex.FindStringSubmatch(id)
	switch {
	case matches == nil || len(matches) < 3:
		return "", "", ""
	case len(matches) == 3:
		return matches[1], matches[2], ""
	default:
		return matches[1], matches[3], matches[2]
	}
}

func idFromPlugin(typ, name, version string) string {
	if version == "" {
		return fmt.Sprintf("%s/name/%s", typ, name)

	}

	return fmt.Sprintf("%s/version/%s/name/%s", typ, version, name)
}

func pluginResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pluginWrite,
		UpdateContext: pluginWrite,
		ReadContext:   pluginRead,
		DeleteContext: pluginDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

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
				Type:                  schema.TypeString,
				Description:           "Semantic version of the plugin.",
				Optional:              true,
				ForceNew:              true,
				DiffSuppressFunc:      diffSuppressEqualSemver,
				DiffSuppressOnRefresh: true,
			},
			fieldSHA256: {
				Type:        schema.TypeString,
				Description: "SHA256 sum of the plugin binary.",
				Required:    true,
			},
			fieldCommand: {
				Type:        schema.TypeString,
				Description: "Command to execute the plugin, relative to the plugin_directory.",
				Required:    true,
			},
			fieldArgs: {
				Type:        schema.TypeList,
				Description: "List of additional arguments to pass to the plugin.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			fieldEnv: {
				Type:        schema.TypeList,
				Description: "List of additional environment variables to run the plugin with in KEY=VALUE form.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Sensitive: true,
			},
			fieldOCIImage: {
				Type:        schema.TypeString,
				Description: "OCI image to run. If specified, setting command, args, and env will update the container's entrypoint, args, and environment variables (append-only) respectively.",
				Optional:    true,
			},
			fieldRuntime: {
				Type:        schema.TypeString,
				Description: "Vault plugin runtime to use if oci_image is specified.",
				Optional:    true,
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
	id := idFromPlugin(pluginType.String(), name, version)

	if diagErr := versionedPluginsSupported(meta, version); diagErr != nil {
		return diagErr
	}

	ociImage := d.Get(fieldOCIImage).(string)
	runtime := d.Get(fieldRuntime).(string)
	if diagErr := containerizedPluginsSupported(meta, ociImage, runtime); diagErr != nil {
		return diagErr
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
		OCIImage: ociImage,
		Runtime:  runtime,
	})
	if err != nil {
		return diag.Errorf("error updating plugin %q: %s", id, err)
	}
	log.Printf("[DEBUG] Wrote plugin %q", id)

	d.SetId(id)

	return pluginRead(ctx, d, meta)
}

func pluginRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	typ, name, version := pluginFromID(d.Id())
	if typ == "" || name == "" {
		diag.Errorf("invalid ID %q, must be of form :type/name/:name or :type/version/:version/name/:name", d.Id())
	}

	if diagErr := versionedPluginsSupported(meta, version); diagErr != nil {
		return diagErr
	}

	pluginType, err := api.ParsePluginType(typ)
	if err != nil {
		return diag.FromErr(err)
	}

	resp, err := client.Sys().GetPluginWithContext(ctx, &api.GetPluginInput{
		Type:    pluginType,
		Name:    name,
		Version: version,
	})

	if err != nil && util.Is404(err) {
		log.Printf("[WARN] plugin %q not found, removing from state", d.Id())
		d.SetId("")
		return nil
	} else if err != nil {
		return diag.Errorf("error reading plugin %q: %s", d.Id(), err)
	}

	result := map[string]any{
		consts.FieldType:    typ,
		consts.FieldName:    name,
		consts.FieldVersion: version,
		fieldSHA256:         resp.SHA256,
		fieldCommand:        resp.Command,
		fieldOCIImage:       resp.OCIImage,
		fieldRuntime:        resp.Runtime,
	}
	if len(resp.Args) > 0 {
		result[fieldArgs] = resp.Args
	}
	for k, v := range result {
		if err := d.Set(k, v); err != nil {
			return diag.Errorf("error setting %q: %s", k, err)
		}
	}

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

	log.Printf("[DEBUG] Removing plugin %q", d.Id())
	err = client.Sys().DeregisterPluginWithContext(ctx, &api.DeregisterPluginInput{
		Type:    pluginType,
		Name:    name,
		Version: version,
	})
	if err != nil {
		return diag.Errorf("error removing plugin %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Removed plugin %q", d.Id())

	return nil
}

func versionedPluginsSupported(meta interface{}, version string) diag.Diagnostics {
	if version != "" && !provider.IsAPISupported(meta, provider.VaultVersion112) {
		return diag.Errorf("plugin version %q specified but versioned plugins are only supported in Vault 1.12 and later", version)
	}

	return nil
}

func containerizedPluginsSupported(meta interface{}, ociImage, runtime string) diag.Diagnostics {
	if (ociImage != "" || runtime != "") && !provider.IsAPISupported(meta, provider.VaultVersion115) {
		return diag.Errorf("plugin oci_image %q and/or runtime %q specified but containerized plugins are only supported in Vault 1.15 and later", ociImage, runtime)
	}

	return nil
}

// diffSuppressEqualSemver is an implementation of schema.SchemaDiffSuppressFunc.
// Vault normalizes plugin versions to have a leading v, so if users specify a
// version without a leading v we use this to suppress the diff.
func diffSuppressEqualSemver(_, oldValue, newValue string, _ *schema.ResourceData) bool {
	oldVersion, err := version.NewSemver(oldValue)
	if err != nil {
		return false
	}
	newVersion, err := version.NewSemver(newValue)
	if err != nil {
		return false
	}
	if oldVersion.Equal(newVersion) {
		return true
	}
	return false
}
