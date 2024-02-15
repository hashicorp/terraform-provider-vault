// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func identityGroupMemberGroupIdsResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: group.GetGroupMemberUpdateContextFunc(group.GroupResourceType),
		UpdateContext: group.GetGroupMemberUpdateContextFunc(group.GroupResourceType),
		ReadContext:   provider.ReadContextWrapper(group.GetGroupMemberReadContextFunc(group.GroupResourceType, false)),
		DeleteContext: group.GetGroupMemberDeleteContextFunc(group.GroupResourceType),

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
