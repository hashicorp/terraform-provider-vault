// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func mfaOktaResource() *schema.Resource {
	return &schema.Resource{
		Create: mfaOktaWrite,
		Update: mfaOktaUpdate,
		Delete: mfaOktaDelete,
		Read:   provider.ReadWrapper(mfaOktaRead),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				Description:  "Name of the MFA method.",
				ValidateFunc: provider.ValidateNoTrailingSlash,
			},
			consts.FieldMountAccessor: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "The mount to tie this method to for use in automatic mappings. " +
					"The mapping will use the Name field of Aliases associated with this mount as the username in the mapping.",
			},
			"username_format": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "A format string for mapping Identity names to MFA method names. Values to substitute should be placed in `{{}}`.",
			},
			"org_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the organization to be used in the Okta API.",
			},
			"api_token": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Sensitive:   true,
				Description: "Okta API key.",
			},
			"base_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "okta.com",
				ForceNew:    true,
				Description: "If set, will be used as the base domain for API requests.",
			},
			"primary_email": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				ForceNew:    true,
				Description: "If set to true, the username will only match the primary email for the account.",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "ID computed by Vault.",
			},
		},
	}
}

func mfaOktaPath(name string) string {
	return "sys/mfa/method/okta/" + strings.Trim(name, "/")
}

func mfaOktaRequestData(d *schema.ResourceData) map[string]interface{} {
	data := map[string]interface{}{}

	if v, ok := d.GetOkExists("primary_email"); ok {
		data["primary_email"] = v.(bool)
	}

	fields := []string{
		"name", "api_token", consts.FieldMountAccessor,
		"username_format", "org_name", "base_url",
	}

	for _, k := range fields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	return data
}

func mfaOktaWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	name := d.Get("name").(string)
	path := mfaOktaPath(name)

	log.Printf("[DEBUG] Creating mfaOkta %s in Vault", name)
	_, err := client.Logical().Write(path, mfaOktaRequestData(d))
	if err != nil {
		return fmt.Errorf("error writing to Vault at %s, err=%w", path, err)
	}

	d.SetId(name)

	return mfaOktaRead(d, meta)
}

func mfaOktaRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := mfaOktaPath(d.Id())

	log.Printf("[DEBUG] Reading MFA Okta config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault at %s, err=%w", path, err)
	}

	fields := []string{
		"name", consts.FieldMountAccessor, "username_format",
		"org_name", "base_url", "primary_email",
		"id",
	}

	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return err
		}
	}

	return nil
}

func mfaOktaUpdate(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func mfaOktaDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := mfaOktaPath(d.Id())

	log.Printf("[DEBUG] Deleting mfaOkta %s from Vault", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting from Vault at %s, err=%w", path, err)
	}

	return nil
}
