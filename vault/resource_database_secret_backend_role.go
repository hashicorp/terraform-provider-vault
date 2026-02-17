// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	databaseSecretBackendRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/roles/.+$")
	databaseSecretBackendRoleNameFromPathRegex    = regexp.MustCompile("^.+/roles/(.+$)")
)

var roleAPIFields = []string{
	consts.FieldDefaultTTL,
	consts.FieldMaxTTL,
	consts.FieldCreationStatements,
	consts.FieldRevocationStatements,
	consts.FieldRollbackStatements,
	consts.FieldRenewStatements,
	consts.FieldCredentialConfig,
	consts.FieldCredentialType,
}

func databaseSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: databaseSecretBackendRoleWrite,
		ReadContext:   provider.ReadContextWrapper(databaseSecretBackendRoleRead),
		UpdateContext: databaseSecretBackendRoleWrite,
		DeleteContext: databaseSecretBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the role.",
			},
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the Database Secret Backend the role belongs to.",
			},
			consts.FieldDBName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Database connection to use for this role.",
			},
			consts.FieldDefaultTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Default TTL for leases associated with this role, in seconds.",
			},
			consts.FieldMaxTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum TTL for leases associated with this role, in seconds.",
			},
			consts.FieldCreationStatements: {
				Type:        schema.TypeList,
				Required:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Database statements to execute to create and configure a user.",
			},
			consts.FieldRevocationStatements: {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Database statements to execute to revoke a user.",
			},
			consts.FieldRollbackStatements: {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Database statements to execute to rollback a create operation in the event of an error.",
			},
			consts.FieldRenewStatements: {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Database statements to execute to renew a user.",
			},
			consts.FieldCredentialType: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the type of credential that will be generated for the role.",
			},
			consts.FieldCredentialConfig: {
				Type:        schema.TypeMap,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the configuration for the given credential_type.",
			},
		},
	}
}

func databaseSecretBackendRoleWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	name := d.Get(consts.FieldName).(string)

	path := databaseSecretBackendRolePath(backend, name)

	data := map[string]interface{}{
		"db_name":             d.Get(consts.FieldDBName),
		"creation_statements": d.Get(consts.FieldCreationStatements),
	}

	for _, k := range roleAPIFields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	log.Printf("[DEBUG] Creating role %q on database backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating role %q for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created role %q on AWS backend %q", name, backend)

	d.SetId(path)
	return databaseSecretBackendRoleRead(ctx, d, meta)
}

func databaseSecretBackendRoleRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	name, err := databaseSecretBackendRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing database role %q because its ID is invalid", path)
		d.SetId("")
		return diag.Errorf("invalid role ID %q: %s", path, err)
	}

	backend, err := databaseSecretBackendRoleBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing database role %q because its ID is invalid", path)
		d.SetId("")
		return diag.Errorf("invalid role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading role from %q", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read role from %q", path)
	if secret == nil {
		log.Printf("[WARN] Role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldDBName, secret.Data[consts.FieldDBName]); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range roleAPIFields {
		if v, ok := secret.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
		} else {
			// For computed fields, explicitly set to nil if not returned by Vault
			// This prevents Terraform from showing "known after apply" in plans
			if k == consts.FieldCredentialConfig {
				if err := d.Set(k, nil); err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}
	return nil
}

func databaseSecretBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Deleting role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted role %q", path)
	return nil
}

func databaseSecretBackendRolePath(backend, name string) string {
	return strings.Trim(backend, "/") + "/roles/" + strings.Trim(name, "/")
}

func databaseSecretBackendRoleNameFromPath(path string) (string, error) {
	if !databaseSecretBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := databaseSecretBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func databaseSecretBackendRoleBackendFromPath(path string) (string, error) {
	if !databaseSecretBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := databaseSecretBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
