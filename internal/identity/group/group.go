package group

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

const (
	LookupPath = "identity/lookup/group"
)

func GetGroupMember(d *schema.ResourceData, resp *api.Secret, memberField string) (map[string]interface{}, error) {
	data := map[string]interface{}{}

	switch memberField {
	case "member_group_ids", "member_entity_ids":
	default:
		return nil, fmt.Errorf("invalid value for member field")
	}
	var curIDS []interface{}
	if t, ok := resp.Data["type"]; ok && t.(string) != "external" {
		if v, ok := resp.Data[memberField]; ok && v != nil {
			curIDS = v.([]interface{})
		}

		if d.Get("exclusive").(bool) || len(curIDS) == 0 {
			data[memberField] = d.Get(memberField).(*schema.Set).List()
		} else {
			set := map[interface{}]bool{}
			for _, v := range curIDS {
				set[v] = true
			}

			o, _ := d.GetChange(memberField)
			if !d.IsNewResource() && o != nil {
				// set.delete()
				for _, i := range o.(*schema.Set).List() {
					delete(set, i)
				}
			}

			if ids, ok := d.GetOk(memberField); ok {
				for _, id := range ids.(*schema.Set).List() {
					// set.add()
					set[id] = true
				}
			}

			// set.keys()
			var result []interface{}
			for k := range set {
				result = append(result, k)
			}
			data[memberField] = result
		}
	}

	return data, nil
}

func SetGroupMember(d *schema.ResourceData, resp *api.Secret, memberField string) error {
	curIDS := resp.Data[memberField]
	if d.Get("exclusive").(bool) {
		if err := d.Set(memberField, curIDS); err != nil {
			return err
		}
	} else {
		set := map[interface{}]bool{}
		if curIDS != nil {
			for _, v := range curIDS.([]interface{}) {
				set[v] = true
			}
		}

		var result []interface{}
		// set.intersection()
		if i, ok := d.GetOk(memberField); ok {
			for _, v := range i.(*schema.Set).List() {
				if _, ok := set[v]; ok {
					result = append(result, v)
				}
			}
		}
		if err := d.Set(memberField, result); err != nil {
			return err
		}
	}

	return nil
}

func DeleteGroupMember(d *schema.ResourceData, resp *api.Secret, memberField string) (map[string]interface{}, error) {
	data := map[string]interface{}{}

	switch memberField {
	case "member_group_ids", "member_entity_ids":
	default:
		return nil, fmt.Errorf("invalid value for member field")
	}

	t, ok := resp.Data["type"]
	if ok && t != "external" {
		if d.Get("exclusive").(bool) {
			data[memberField] = make([]string, 0)
		} else {
			set := map[interface{}]bool{}
			if v, ok := resp.Data[memberField]; ok && v != nil {
				for _, id := range v.([]interface{}) {
					set[id] = true
				}
			}

			result := []interface{}{}
			if len(set) > 0 {
				if v, ok := d.GetOk(memberField); ok {
					for _, id := range v.(*schema.Set).List() {
						delete(set, id)
					}
				}

				for k := range set {
					result = append(result, k)
				}
			}
			data[memberField] = result
		}
	}

	return data, nil
}

// needed for testing
type GroupMemberTester struct {
	EntityIDS []string
	GroupIDS  []string
}

func (r *GroupMemberTester) SetMemberEntities(resource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		result, err := r.getGroupMemberResourceData(s, resource, "member_entity_ids")
		if err != nil {
			return err
		}
		r.EntityIDS = result
		return nil
	}
}

func (r *GroupMemberTester) SetMemberGroups(resource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		result, err := r.getGroupMemberResourceData(s, resource, "member_group_ids")
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
