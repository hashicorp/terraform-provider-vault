// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func tencentCloudSecretBackendRoleResource(name string) *schema.Resource {
	return &schema.Resource{
		Create: tencentCloudSecretBackendRoleWrite,
		Read:   provider.ReadWrapper(tencentCloudSecretBackendRoleRead),
		Update: tencentCloudSecretBackendRoleWrite,
		Delete: tencentCloudSecretBackendRoleDelete,
		Exists: tencentCloudSecretBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Specifies the name of the role to generate credentials against. This is part of the request URL.",
			},
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the Tencent Cloud Secret Backend the role belongs to.",
			},
			"role_arn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The ARN of a role that will be assumed to obtain STS credentials.",
			},
			"remote_policies": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "The names and types of a pre-existing policies to be applied to the generate access token. Example: 'name: ReadOnlyAccess,type:-'",
			},
			"inline_policies": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "The policy document JSON to be generated and attached to the access token.",
				//ValidateFunc:     ValidateDataJSONFunc(name),
				//DiffSuppressFunc: util.JsonDiffSuppress,
			},
			"ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The duration in seconds after which the issued token should expire. Defaults to 0, in which case the value will fallback to the system/mount defaults.",
			},
			"max_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The maximum allowed lifetime of tokens issued using this role.",
			},
		},
	}
}

func tencentCloudSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Get("name").(string)
	backend := d.Get("backend").(string)

	data := map[string]interface{}{}
	roleArn := d.Get("role_arn").(string)
	remotePolicy := d.Get("remote_policies").(*schema.Set).List()
	inlinePolicy := d.Get("inline_policies").(*schema.Set).List()

	if roleArn == "" && len(remotePolicy) == 0 && len(inlinePolicy) == 0 {
		return fmt.Errorf("at least one of: `role_arn`, `remote_policies` or `inline_policies` must be set")
	}

	if d.HasChange("remote_policies") {
		data["remote_policies"] = remotePolicy
	}
	if d.HasChange("inline_policies") {
		data["inline_policies"] = inlinePolicy
	}
	if d.HasChange("role_arn") {
		data["role_arn"] = roleArn
	}

	if v, ok := d.GetOkExists("ttl"); ok {
		data["ttl"] = v.(int)
	}
	if v, ok := d.GetOkExists("max_ttl"); ok {
		data["max_ttl"] = v.(int)
	}

	log.Printf("[DEBUG] Creating role %q on AWS backend %q", name, backend)
	_, err := client.Logical().Write(backend+"/role/"+name, data)
	if err != nil {
		return fmt.Errorf("error creating role %q for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created role %q on AWS backend %q", name, backend)

	d.SetId(backend + "/role/" + name)
	return tencentCloudSecretBackendRoleRead(d, meta)
}

func tencentCloudSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	pathPieces := strings.Split(path, "/")
	if len(pathPieces) < 3 || pathPieces[len(pathPieces)-2] != "role" {
		return fmt.Errorf("invalid id %q; must be {backend}/role/{name}", path)
	}

	log.Printf("[DEBUG] Reading role from %q", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read role from %q", path)
	if secret == nil {
		log.Printf("[WARN] Role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if v, ok := secret.Data["remote_policies"]; ok {
		_ = d.Set("remote_policies", v)
	}

	if v, ok := secret.Data["inline_policies"]; ok {
		_ = d.Set("inline_policies", v)
	}

	if v, ok := secret.Data["role_arn"]; ok {
		_ = d.Set("role_arn", v)
	}

	if v, ok := secret.Data["ttl"]; ok {
		_ = d.Set("ttl", v)
	}
	if v, ok := secret.Data["max_ttl"]; ok {
		_ = d.Set("max_ttl", v)
	}

	_ = d.Set("backend", strings.Join(pathPieces[:len(pathPieces)-2], "/"))
	_ = d.Set("name", pathPieces[len(pathPieces)-1])
	return nil
}

func tencentCloudSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Deleting role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted role %q", path)
	return nil
}

func tencentCloudSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return secret != nil, nil
}
