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

func mfaPingIDResource() *schema.Resource {
	return &schema.Resource{
		Create: mfaPingIDWrite,
		Update: mfaPingIDUpdate,
		Delete: mfaPingIDDelete,
		Read:   provider.ReadWrapper(mfaPingIDRead),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Name of the MFA method.",
				ForceNew:     true,
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
			"settings_file_base64": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "A base64-encoded third-party settings file retrieved from PingID's configuration page.",
			},
			"idp_url": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "IDP URL computed by Vault.",
			},
			"admin_url": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Admin URL computed by Vault.",
			},
			"authenticator_url": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Authenticator URL computed by Vault.",
			},
			"org_alias": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Org Alias computed by Vault.",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "ID computed by Vault.",
			},
			consts.FieldNamespaceID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Namespace ID computed by Vault.",
			},
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Type of configuration computed by Vault.",
			},
			"use_signature": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "If set, enables use of PingID signature. Computed by Vault",
			},
		},
	}
}

func mfaPingIDPath(name string) string {
	return "sys/mfa/method/pingid/" + strings.Trim(name, "/")
}

func mfaPingIDRequestData(d *schema.ResourceData) map[string]interface{} {
	data := map[string]interface{}{}

	fields := []string{
		"name", consts.FieldMountAccessor, "settings_file_base64",
		"username_format",
	}

	for _, k := range fields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	return data
}

func mfaPingIDWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	name := d.Get("name").(string)
	path := mfaPingIDPath(name)

	log.Printf("[DEBUG] Creating mfaPingID %s in Vault", name)
	_, err := client.Logical().Write(path, mfaPingIDRequestData(d))
	if err != nil {
		return fmt.Errorf("error writing to Vault at %s, err=%w", path, err)
	}

	d.SetId(name)

	return mfaPingIDRead(d, meta)
}

func mfaPingIDRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := mfaPingIDPath(d.Id())

	log.Printf("[DEBUG] Reading MFA PingID config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault at %s, err=%w", path, err)
	}

	if err := d.Set(consts.FieldMountAccessor, d.Get(consts.FieldMountAccessor)); err != nil {
		return err
	}

	if err := d.Set("username_format", d.Get("username_format")); err != nil {
		return err
	}

	if err := d.Set("settings_file_base64", d.Get("settings_file_base64")); err != nil {
		return err
	}

	fields := []string{
		"name", "idp_url", "admin_url",
		"authenticator_url", "org_alias", "type",
		"use_signature", "id", consts.FieldNamespaceID,
	}

	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return err
		}
	}

	return nil
}

func mfaPingIDUpdate(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func mfaPingIDDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := mfaPingIDPath(d.Id())

	log.Printf("[DEBUG] Deleting mfaPingID %s from Vault", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting from Vault at %s, err=%w", path, err)
	}

	return nil
}
