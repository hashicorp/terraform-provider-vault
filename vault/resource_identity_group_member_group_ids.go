package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func identityGroupMemberGroupIdsResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: identityGroupMemberGroupIdsUpdate,
		UpdateContext: identityGroupMemberGroupIdsUpdate,
		ReadContext:   ReadContextWrapper(identityGroupMemberGroupIdsRead),
		DeleteContext: identityGroupMemberGroupIdsDelete,

		Schema: map[string]*schema.Schema{
			consts.FieldMemberGroupIDs: {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Group IDs to be assigned as group members.",
			},
			consts.FieldExclusive: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
				Description: `If set to true, allows the resource to manage member group ids
exclusively. Beware of race conditions when disabling exclusive management`,
			},
			consts.FieldGroupID: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "ID of the group.",
			},
		},
	}
}

func identityGroupMemberGroupIdsUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	gid := d.Get(consts.FieldGroupID).(string)
	path := group.IdentityGroupIDPath(gid)
	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	if diag := group.UpdateGroupMemberContextFunc(d, client, consts.FieldMemberGroupIDs); diag != nil {
		return diag
	}

	return identityGroupMemberGroupIdsRead(ctx, d, meta)
}

func identityGroupMemberGroupIdsRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	return group.ReadGroupMemberContextFunc(d, client, consts.FieldMemberGroupIDs, false)
}

func identityGroupMemberGroupIdsDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	id := d.Get(consts.FieldGroupID).(string)
	path := group.IdentityGroupIDPath(id)
	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	return group.DeleteGroupMemberContextFunc(d, client, consts.FieldMemberGroupIDs)
}
