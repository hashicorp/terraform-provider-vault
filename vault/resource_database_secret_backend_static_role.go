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
	databaseSecretBackendStaticRoleBackendFromPathRegex = regexp.MustCompile("^(.+)/static-roles/.+$")
	databaseSecretBackendStaticRoleNameFromPathRegex    = regexp.MustCompile("^.+/static-roles/(.+$)")
)

var optionalStaticRoleAPIFields = []string{
	consts.FieldRotationStatements,
	consts.FieldCredentialType,
	consts.FieldCredentialConfig,
}

func databaseSecretBackendStaticRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: databaseSecretBackendStaticRoleWrite,
		ReadContext:   provider.ReadContextWrapper(databaseSecretBackendStaticRoleRead),
		UpdateContext: databaseSecretBackendStaticRoleWrite,
		DeleteContext: databaseSecretBackendStaticRoleDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the static role.",
			},
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the Database Secret Backend the role belongs to.",
			},
			consts.FieldUsername: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The database username that this role corresponds to.",
			},
			consts.FieldRotationPeriod: {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "The amount of time Vault should wait before rotating the password, in seconds.",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(int)
					if value < 5 {
						errs = append(errs, fmt.Errorf("The minimum value of rotation_period is 5 seconds."))
					}
					return
				},
			},
			consts.FieldDBName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Database connection to use for this role.",
			},
			consts.FieldRotationStatements: {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Database statements to execute to rotate the password for the configured database user.",
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
				Description: "Specifies the configuration for the given credential_type.",
			},
		},
	}
}

func databaseSecretBackendStaticRoleWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	name := d.Get(consts.FieldName).(string)

	path := databaseSecretBackendStaticRolePath(backend, name)

	data := map[string]interface{}{
		"username":        d.Get(consts.FieldUsername),
		"rotation_period": d.Get(consts.FieldRotationPeriod),
		"db_name":         d.Get(consts.FieldDBName),
	}

	for _, k := range optionalStaticRoleAPIFields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	log.Printf("[DEBUG] Creating static role %q on database backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating static role %q for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created static role %q on database backend %q", name, backend)

	d.SetId(path)
	return databaseSecretBackendStaticRoleRead(ctx, d, meta)
}

func databaseSecretBackendStaticRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	name, err := databaseSecretBackendStaticRoleNameFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing database static role %q because its ID is invalid", path)
		d.SetId("")
		return diag.Errorf("invalid static role ID %q: %s", path, err)
	}

	backend, err := databaseSecretBackendStaticRoleBackendFromPath(path)
	if err != nil {
		log.Printf("[WARN] Removing database static role %q because its ID is invalid", path)
		d.SetId("")
		return diag.Errorf("invalid static role ID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading static role from %q", path)
	role, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading static role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read static role from %q", path)
	if role == nil {
		log.Printf("[WARN] Static role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldDBName, role.Data[consts.FieldDBName]); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldUsername, role.Data[consts.FieldUsername]); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldRotationPeriod, role.Data[consts.FieldRotationPeriod]); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range optionalStaticRoleAPIFields {
		if v, ok := role.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
		}
	}
	return nil
}

func databaseSecretBackendStaticRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Deleting static role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting static role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted static role %q", path)
	return nil
}

func databaseSecretBackendStaticRolePath(backend, name string) string {
	return strings.Trim(backend, "/") + "/static-roles/" + strings.Trim(name, "/")
}

func databaseSecretBackendStaticRoleNameFromPath(path string) (string, error) {
	if !databaseSecretBackendStaticRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := databaseSecretBackendStaticRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func databaseSecretBackendStaticRoleBackendFromPath(path string) (string, error) {
	if !databaseSecretBackendStaticRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := databaseSecretBackendStaticRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
