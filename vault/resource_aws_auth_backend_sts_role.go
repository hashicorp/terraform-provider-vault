// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	awsAuthBackendSTSRoleBackendFromPathRegex   = regexp.MustCompile("^auth/(.+)/config/sts/.+$")
	awsAuthBackendSTSRoleAccountIDFromPathRegex = regexp.MustCompile("^auth/.+/config/sts/(.+)$")
)

func awsAuthBackendSTSRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: awsAuthBackendSTSRoleCreate,
		Read:   provider.ReadWrapper(awsAuthBackendSTSRoleRead),
		Update: awsAuthBackendSTSRoleUpdate,
		Delete: awsAuthBackendSTSRoleDelete,
		Exists: awsAuthBackendSTSRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"account_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "AWS account ID to be associated with STS role.",
			},
			"sts_role": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "AWS ARN for STS role to be assumed when interacting with the account specified.",
			},
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "aws",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			consts.FieldExternalID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "External ID expected by the STS role.",
			},
		},
	}
}

func awsAuthBackendSTSRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	accountID := d.Get("account_id").(string)
	stsRole := d.Get("sts_role").(string)
	externalID := d.Get(consts.FieldExternalID).(string)

	path := awsAuthBackendSTSRolePath(backend, accountID)

	data := map[string]interface{}{
		"sts_role": stsRole,
	}

	if provider.IsAPISupported(meta, provider.VaultVersion117) {
		data[consts.FieldExternalID] = externalID
	}

	log.Printf("[DEBUG] Writing STS role %q to AWS auth backend", path)
	_, err := client.Logical().Write(path, data)

	d.SetId(path)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("error writing STS role %q to AWS auth backend: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote STS role %q to AWS auth backend", path)

	return awsAuthBackendSTSRoleRead(d, meta)
}

func awsAuthBackendSTSRoleRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	backend, err := awsAuthBackendSTSRoleBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for AWS auth backend STS role: %s", path, err)
	}

	accountID, err := awsAuthBackendSTSRoleAccountIDFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for AWS auth backend STS role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading STS role %q from AWS auth backend", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading STS role %q from AWS auth backend %s", path, err)
	}
	log.Printf("[DEBUG] Read STS role %q from AWS auth backend", path)
	if resp == nil {
		log.Printf("[WARN} AWS auth backend STS role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set("backend", backend)
	d.Set("account_id", accountID)
	d.Set("sts_role", resp.Data["sts_role"])

	if provider.IsAPISupported(meta, provider.VaultVersion117) {
		if v, ok := resp.Data[consts.FieldExternalID]; ok {
			if err := d.Set(consts.FieldExternalID, v); err != nil {
				return err
			}
		}
	}

	return nil
}

func awsAuthBackendSTSRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	stsRole := d.Get("sts_role").(string)
	externalID := d.Get(consts.FieldExternalID).(string)

	path := d.Id()

	data := map[string]interface{}{
		"sts_role": stsRole,
	}

	if provider.IsAPISupported(meta, provider.VaultVersion117) {
		data[consts.FieldExternalID] = externalID
	}

	log.Printf("[DEBUG] Updating STS role %q in AWS auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating STS role %q in AWS auth backend", path)
	}
	log.Printf("[DEBUG] Updated STS role %q in AWS auth backend", path)

	return awsAuthBackendSTSRoleRead(d, meta)
}

func awsAuthBackendSTSRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Deleting STS role %q from AWS auth backend", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting STS role %q from AWS auth backend", path)
	}
	log.Printf("[DEBUG] Deleted STS role %q from AWS auth backend", path)

	return nil
}

func awsAuthBackendSTSRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if STS role %q exists in AWS auth backend", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if STS role %q exists in AWS auth backend: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if STS role %q exists in AWS auth backend", path)

	return resp != nil, nil
}

func awsAuthBackendSTSRolePath(backend, account string) string {
	return "auth/" + strings.Trim(backend, "/") + "/config/sts/" + strings.Trim(account, "/")
}

func awsAuthBackendSTSRoleBackendFromPath(path string) (string, error) {
	if !awsAuthBackendSTSRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := awsAuthBackendSTSRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func awsAuthBackendSTSRoleAccountIDFromPath(path string) (string, error) {
	if !awsAuthBackendSTSRoleAccountIDFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no account ID found")
	}
	res := awsAuthBackendSTSRoleAccountIDFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for account ID", len(res))
	}
	return res[1], nil
}
