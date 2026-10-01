// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func scimClientResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: scimClientCreate,
		ReadContext:   provider.ReadContextWrapper(scimClientRead),
		UpdateContext: scimClientUpdate,
		DeleteContext: scimClientDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Timeouts: &schema.ResourceTimeout{
			Delete: schema.DefaultTimeout(10 * time.Minute),
		},
		Schema: map[string]*schema.Schema{
			consts.FieldSCIMClientName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the SCIM client.",
			},
			consts.FieldAccessGrantPrincipal: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Entity ID authorized to call SCIM protocol endpoints on behalf of this client.",
			},
			consts.FieldAliasMountAccessor: {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Auth mount accessor used to create entity aliases for SCIM users. Immutable after creation.",
			},
			consts.FieldDefaultSchemaVersion: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ValidateFunc: validation.StringInSlice([]string{
					"",
					"2.0",
					"2.2",
				}, false),
				Description: "The Vault SCIM extension schema version used for this client. Must be " +
					"\"2.0\" or \"2.2\". Leave unset to use Vault's default for new clients (\"2.2\").",
			},
			consts.FieldAllowUserAdoption: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to allow adoption of existing Vault entities by SCIM users.",
			},
			consts.FieldAllowGroupAdoption: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to allow adoption of existing Vault groups by SCIM-provisioned groups.",
			},
			consts.FieldAllowedExtraAliasMountAccessors: {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Additional mount accessors whose aliases may be managed by this SCIM client.",
			},
			consts.FieldMaxActiveTokens: {
				Type:         schema.TypeInt,
				Optional:     true,
				Computed:     true,
				ValidateFunc: validation.IntAtLeast(1),
				Description: "Maximum number of active tokens for this SCIM client. Must be a positive " +
					"non-zero value. Leave unset to use Vault's default (2).",
			},
			consts.FieldMaxTokenTTL: {
				Type:         schema.TypeInt,
				Optional:     true,
				Computed:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Description: "Maximum TTL (in seconds) for tokens issued to this SCIM client. Zero means " +
					"the cluster default is used.",
			},
			consts.FieldDeletionPolicy: {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "",
				ValidateFunc: validation.StringInSlice([]string{
					"",
					consts.DeletionPolicyOrphanChildResources,
					consts.DeletionPolicyDeleteChildResources,
				}, false),
				Description: "Controls how linked entities/groups/aliases are handled when this " +
					"resource is destroyed. `orphan_child_resources` detaches managed resources " +
					"without deleting them; `delete_child_resources` deletes all managed resources " +
					"along with the client. Leave unset for a plain delete (fails if the client still " +
					"owns linked resources). Only consulted at destroy time.",
			},

			// consts.FieldUnlinkResources: {
			// 	Type:     schema.TypeBool,
			// 	Optional: true,
			// 	Default:  false,
			// 	Description: "On destroy, detach managed entities/groups/aliases from this SCIM client " +
			// 		"without deleting them. Mutually exclusive with delete_linked_resources.",
			// },
			consts.FieldClientID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client ID assigned by Vault.",
			},
			consts.FieldDeleting: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True while Vault is asynchronously cleaning up resources owned by this client.",
			},
		},
	}
}

/*

// Optimize this function so that is reads only once

*/
// scimClientCreate handles Terraform "create" for a vault_scim_client resource.
// It POSTs the new SCIM client config to Vault and reads back the full state
// afterward so all computed fields are populated.
func scimClientCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	//Get an authenticated Vault API client for the current provider config.
	client, er := provider.GetClient(d, meta)
	if er != nil {
		return diag.FromErr(er)
	}

	// SCIM clients are addressed by name in Vault where the API path is built from.
	name := d.Get(consts.FieldSCIMClientName).(string)
	path := fmt.Sprintf("identity/scim/client/%s", name)

	// acccess_grant_principle is the only required field besides the name.
	data := map[string]interface{}{
		consts.FieldAccessGrantPrincipal: d.Get(consts.FieldAccessGrantPrincipal),
	}

	// Everything else is optional so only send the fields the user actually set,
	// so Vault's own server side defaults apply when a field is left out of
	// the Terraform config.
	optionalFields := []string{
		consts.FieldAliasMountAccessor,
		consts.FieldDefaultSchemaVersion,
		consts.FieldAllowUserAdoption,
		consts.FieldAllowGroupAdoption,
		consts.FieldAllowedExtraAliasMountAccessors,
		consts.FieldMaxActiveTokens,
		consts.FieldMaxTokenTTL,
	}

	for _, f := range optionalFields {
		if v, ok := d.GetOk(f); ok {
			data[f] = v
		}
	}

	// Send the create request to Vault.
	resp, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error creating SCIM client %q: %s", name, err)
	}

	// The client_name is used as the Terraform resource ID (not client_id),
	// since that's what the SCIM client API path is keyed on and what
	// `terraform import` will use to look the resource up.
	d.SetId(name)

	// A create returns the full client object in th response body,
	// including the server generated client_id.
	if resp != nil {
		if v, ok := resp.Data[consts.FieldClientID]; ok {
			if err := d.Set(consts.FieldClientID, v); err != nil {
				return diag.Errorf("error setting %q: %s", consts.FieldClientID, err)
			}
		}
	}

	// Re-read from Vault so Terraform state picks up every remaining
	// computed/defaulted field (e.g. default_schema_version, deleting)
	// exactly as Vault stored them, not just what we sent above.
	return scimClientRead(ctx, d, meta)

}

func scimClientRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// Get an authenticated Vault API client for the current provider config.
	client, er := provider.GetClient(d, meta)
	if er != nil {
		return diag.FromErr(er)
	}

	// The Terraform resource ID is the client_name.
	// Using the resource ID to build the API Path
	name := d.Id()
	path := fmt.Sprintf("identity/scim/client/%s", name)

	// Fetch the client's current config from Vault.
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(err)
	}
	if resp == nil {
		// Resource no longer exists in Vault; remove from state.
		d.SetId("")
		return nil
	}

	// List every field this resource tracks. Iterating over a
	// known list to keep in control of which fields get written into
	// the Terraform state.
	fields := []string{
		consts.FieldSCIMClientName,
		consts.FieldClientID,
		consts.FieldAccessGrantPrincipal,
		consts.FieldAliasMountAccessor,
		consts.FieldDefaultSchemaVersion,
		consts.FieldAllowUserAdoption,
		consts.FieldAllowGroupAdoption,
		consts.FieldAllowedExtraAliasMountAccessors,
		consts.FieldMaxActiveTokens,
		consts.FieldMaxTokenTTL,
		consts.FieldDeleting,
	}
	for _, f := range fields {
		// `ok` skips any field Vault didn't return, instead of setting
		// a zero value that could overwrite valid existing state.
		if v, ok := resp.Data[f]; ok {
			if err := d.Set(f, v); err != nil {
				return diag.Errorf("error setting %q: %s", f, err)
			}
		}
	}

	return nil
}

// scimClientUpdate handles Terraform "update" for a vault_scim_client resource.
// It sends only the fields that actually changed, since Vault preserves any
// field that's omitted from the request rather than resetting it. Unlike
// `Create`, this always ends with a `Read` call, because Vault's update response
// has no body to read state from directly.
func scimClientUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	// Get an authenticated Vault API client for the current provider config.
	client, er := provider.GetClient(d, meta)
	if er != nil {
		return diag.FromErr(er)
	}

	// The Terraform resource ID is the client_name.
	// Using the resource ID to build the API Path
	name := d.Id()
	path := fmt.Sprintf("identity/scim/client/%s", name)

	// access_grant_principal is always sent on update
	// since it's the field that the API expects on every write.
	data := map[string]interface{}{
		consts.FieldAccessGrantPrincipal: d.Get(consts.FieldAccessGrantPrincipal),
	}

	// alias_mount_accessor is ForceNew, so its value can never change here, but
	// Vault treats an omitted alias_mount_accessor on an existing client as an
	// attempt to clear it and rejects the request. Always resend the current
	// value when one is set.
	if v, ok := d.GetOk(consts.FieldAliasMountAccessor); ok {
		data[consts.FieldAliasMountAccessor] = v
	}

	// client_name is also ForceNew. The remaining mutable fields are only sent
	// when they changed, for an in place update.
	updatableFields := []string{
		consts.FieldDefaultSchemaVersion,
		consts.FieldAllowUserAdoption,
		consts.FieldAllowGroupAdoption,
		consts.FieldAllowedExtraAliasMountAccessors,
		consts.FieldMaxActiveTokens,
		consts.FieldMaxTokenTTL,
	}
	for _, f := range updatableFields {
		if d.HasChange(f) {
			data[f] = d.Get(f)
		}
	}

	if _, err := client.Logical().WriteWithContext(ctx, path, data); err != nil {
		return diag.Errorf("error updating SCIM client %q: %s", name, err)
	}
	return scimClientRead(ctx, d, meta)
}

// scimClientDelete handles Terraform `destroy` for a vault_scim_client resource.
// Deleting a SCIM client that still owns entities/groups is async in Vault, so
// this issues the delete request and then polls until Vault confirms the
// client is actually gone, rather than assuming success right away.
func scimClientDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// Get an authenticated Vault API client for the current provider config.
	client, er := provider.GetClient(d, meta)
	if er != nil {
		return diag.FromErr(er)
	}

	// The Terraform resource ID is the client_name.
	// Using the resource ID to build the API Path
	name := d.Id()
	path := fmt.Sprintf("identity/scim/client/%s", name)

	// deletion_policy is a single Terraform facing field, but Vault's `DELETE`
	// endpoint actually expects one of two separate query string flags. Map
	// the one Terraform value onto the correct Vault query param here. Leaving
	// deletion_policy unset sends a plain delete with no query params, which
	// only succeeds if the client has no linked entities/groups.
	//
	// The flags are sent as query parameters via DeleteWithData. Appending
	// "?..." to the path instead would be percent-encoded into the path itself
	// and Vault would answer "unsupported path".
	var query map[string][]string

	switch d.Get(consts.FieldDeletionPolicy).(string) {
	case consts.DeletionPolicyDeleteChildResources:
		// Delete the client AND everything it owns (entities/groups/aliases)
		query = map[string][]string{"delete-linked-resources": {"true"}}
	case consts.DeletionPolicyOrphanChildResources:
		// Detach owned resources from the client without deleting them,
		// then remove the client itself.
		query = map[string][]string{"unlink-resources": {"true"}}
	}

	// Begin deletion. Vault marks the client as "deleting" and starts
	// cleanup in the background rather than finishing synchronously.
	if _, err := client.Logical().DeleteWithDataWithContext(ctx, path, query); err != nil {
		return diag.Errorf("error deleting SCIM client %q: %s", name, err)
	}

	// Poll Vault until the client is fully gone. This resource introduces the
	// StateChangeConf pattern to this repo because the SCIM client deletion
	// is asynchronous. A single `DELETE` call isn't guaranteed to mean
	// that the client and any linked resources are actually removed.
	stateConf := &retry.StateChangeConf{
		Pending: []string{"deleting"},
		Target:  []string{"deleted"},
		Refresh: func() (interface{}, string, error) {
			// Keep checking whether the client still exists.
			resp, err := client.Logical().ReadWithContext(ctx, path)
			if err != nil {
				return nil, "", err
			}
			if resp == nil {
				// Vault finished removing the client.
				return "deleted", "deleted", nil
			}
			// Still present, keep polling.
			return resp, "deleting", nil
		},
		Timeout:    d.Timeout(schema.TimeoutDelete),
		Delay:      2 * time.Second,
		MinTimeout: 2 * time.Second,
	}
	if _, err := stateConf.WaitForStateContext(ctx); err != nil {
		return diag.Errorf("error waiting for SCIM client %q deletion: %s", name, err)
	}

	// Returning nil tells Terraform the destroy succeeded,
	// so it removes the resource from state.
	return nil
}
