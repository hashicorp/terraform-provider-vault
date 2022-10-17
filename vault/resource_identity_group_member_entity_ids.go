package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func identityGroupMemberEntityIdsResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: identityGroupMemberEntityIdsUpdate,
		UpdateContext: identityGroupMemberEntityIdsUpdate,
		ReadContext:   ReadContextWrapper(identityGroupMemberEntityIdsRead),
		DeleteContext: identityGroupMemberEntityIdsDelete,

		Schema: map[string]*schema.Schema{
			consts.FieldMemberEntityIDs: {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Entity IDs to be assigned as group members.",
			},
			consts.FieldExclusive: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
				Description: `If set to true, allows the resource to manage member entity ids
exclusively. Beware of race conditions when disabling exclusive management`,
			},
			consts.FieldGroupID: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "ID of the group.",
			},
			consts.FieldGroupName: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the group.",
				Deprecated: `The value for group_name may not always be accurate, 
use "data.vault_identity_group.*.group_name", "vault_identity_group.*.group_name" instead`,
			},
		},
	}
}

func identityGroupMemberEntityIdsUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	gid := d.Get(consts.FieldGroupID).(string)
	path := group.IdentityGroupIDPath(gid)
	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	if diag := group.UpdateGroupMemberContextFunc(d, client, consts.FieldMemberEntityIDs); diag != nil {
		return diag
	}

	return identityGroupMemberEntityIdsRead(ctx, d, meta)
}

func identityGroupMemberEntityIdsRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	return group.ReadGroupMemberContextFunc(d, client, consts.FieldMemberEntityIDs, true)
}

func identityGroupMemberEntityIdsDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	id := d.Get(consts.FieldGroupID).(string)
	path := group.IdentityGroupIDPath(id)
	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	return group.DeleteGroupMemberContextFunc(d, client, consts.FieldMemberEntityIDs)
}
