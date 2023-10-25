// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func userpassUserResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldMount: {
			Type:         schema.TypeString,
			Optional:     true,
			ForceNew:     true,
			Description:  "Path where the userpass auth backend is mounted.",
			Default:      consts.MountTypeUserpass,
			ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
		},
		consts.FieldUsername: {
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			Description:  "The username for the user.",
			ValidateFunc: provider.ValidateStringSlug,
		},
		consts.FieldPassword: {
			Type:        schema.TypeString,
			Required:    true,
			Sensitive:   true,
			Description: "The password for the user.",
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		CreateContext: userpassUserCreate,
		ReadContext:   ReadContextWrapper(userpassUserRead),
		UpdateContext: userpassUserUpdate,
		DeleteContext: userpassUserDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

var (
	userpassMountFromPathRegex    = regexp.MustCompile("^auth/(.+)/users/.+$")
	userpassUsernameFromPathRegex = regexp.MustCompile("^auth/.+/users/(.+)$")
)

func userPath(mount string, username string) string {
	return fmt.Sprintf("auth/%s/users/%s", mount, username)
}

func mountFromPath(path string) (string, error) {
	if !userpassMountFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no mount found")
	}
	res := userpassMountFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for mount", len(res))
	}
	return res[1], nil
}

func usernameFromPath(path string) (string, error) {
	if !userpassUsernameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := userpassUsernameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for username", len(res))
	}
	return res[1], nil
}

func userpassUserCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	log.Printf("[INFO] Creating user %s at mount %s", d.Get(consts.FieldUsePasscode).(string), d.Get(consts.FieldMount).(string))
	return userpassUserUpdate(ctx, d, meta)
}

func userpassUserUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	data := map[string]interface{}{}

	updateTokenFields(d, data, false)

	if v, ok := d.GetOk(consts.FieldUsername); ok {
		data[consts.FieldUsername] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldPassword); ok {
		data[consts.FieldPassword] = v.(string)
	}

	path := userPath(d.Get(consts.FieldMount).(string), d.Get(consts.FieldUsername).(string))
	_, err := client.Logical().Write(path, data)
	if err != nil {
		log.Printf("[ERROR] Error writing user at '%s'", path)
		return diag.FromErr(err)
	}
	d.SetId(path)

	log.Printf("[INFO] Saved user at '%v'", path)

	return userpassUserRead(ctx, d, meta)
}

func userpassUserRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	dt, err := client.Logical().Read(path)
	if err != nil || dt == nil {
		d.SetId("")
		log.Printf("[ERROR] Error reading user from '%s'", path)
		return diag.FromErr(err)
	}

	mount, err := mountFromPath(path)
	if err != nil {
		return diag.FromErr(err)
	}
	d.Set(consts.FieldMount, mount)

	username, err := usernameFromPath(path)
	if err != nil {
		return diag.FromErr(err)
	}
	d.Set(consts.FieldUsername, username)

	readTokenFields(d, dt)

	return nil
}

func userpassUserDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	_, err := client.Logical().Delete(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	return nil
}
