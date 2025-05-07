// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package group

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// needed for testing
type GroupMemberTester struct {
	EntityIDS []string
	GroupIDS  []string
}

func (r *GroupMemberTester) SetMemberEntities(resource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		result, err := r.getGroupMemberResourceData(s, resource, consts.FieldMemberEntityIDs)
		if err != nil {
			return err
		}
		r.EntityIDS = result
		return nil
	}
}

func (r *GroupMemberTester) SetMemberGroups(resource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		result, err := r.getGroupMemberResourceData(s, resource, consts.FieldMemberGroupIDs)
		if err != nil {
			return err
		}
		r.GroupIDS = result
		return nil
	}
}

func (r *GroupMemberTester) getGroupMemberResourceData(s *terraform.State, resource, memberField string) ([]string, error) {
	var result []string
	resourceState := s.Modules[0].Resources[resource]
	if resourceState == nil {
		return result, fmt.Errorf("resource not found in state")
	}

	instanceState := resourceState.Primary
	if instanceState == nil {
		return result, fmt.Errorf("resource not found in state")
	}

	count, err := strconv.Atoi(instanceState.Attributes[fmt.Sprintf("%s.#", memberField)])
	if err != nil {
		return nil, err
	}

	for i := 0; i < count; i++ {
		k := fmt.Sprintf("%s.%d", memberField, i)
		result = append(result, instanceState.Attributes[k])
	}

	return result, nil
}

func (r *GroupMemberTester) CheckMemberEntities(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for i, v := range r.EntityIDS {
			k := fmt.Sprintf("member_entity_ids.%d", i)
			f := resource.TestCheckResourceAttr(resourceName, k, v)
			if err := f(s); err != nil {
				return err
			}
		}
		return nil
	}
}

func (r *GroupMemberTester) CheckMemberGroups(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for i, v := range r.GroupIDS {
			k := fmt.Sprintf("member_group_ids.%d", i)
			f := resource.TestCheckResourceAttr(resourceName, k, v)
			if err := f(s); err != nil {
				return err
			}
		}
		return nil
	}
}
