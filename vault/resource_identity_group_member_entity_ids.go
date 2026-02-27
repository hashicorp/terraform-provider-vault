// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func identityGroupMemberEntityIdsResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: group.GetGroupMemberUpdateContextFunc(group.EntityResourceType),
		UpdateContext: group.GetGroupMemberUpdateContextFunc(group.EntityResourceType),
		ReadContext:   provider.ReadContextWrapper(group.GetGroupMemberReadContextFunc(group.EntityResourceType)),
		DeleteContext: group.GetGroupMemberDeleteContextFunc(group.EntityResourceType),

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
		},
	}
}
