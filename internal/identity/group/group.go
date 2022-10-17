package group

import (
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/entity"
)

const (
	LookupPath        = "identity/lookup/group"
	IdentityGroupPath = "/identity/group"
)

func IdentityGroupIDPath(id string) string {
	return fmt.Sprintf("%s/id/%s", IdentityGroupPath, id)
}

// This function may return `nil` for the IdentityGroup if it does not exist
func ReadIdentityGroup(client *api.Client, groupID string, retry bool) (*api.Secret, error) {
	path := IdentityGroupIDPath(groupID)
	log.Printf("[DEBUG] Reading IdentityGroup %s from %q", groupID, path)

	return entity.ReadEntity(client, path, retry)
}

func IsIdentityNotFoundError(err error) bool {
	return err != nil && errors.Is(err, entity.ErrEntityNotFound)
}

func UpdateGroupMemberContextFunc(d *schema.ResourceData, client *api.Client, memberField string) diag.Diagnostics {
	gid := d.Get(consts.FieldGroupID).(string)
	path := IdentityGroupIDPath(gid)

	log.Printf("[DEBUG] Updating field %q on Identity Group %q", memberField, gid)

	if d.HasChange(consts.FieldGroupID) {
		o, n := d.GetChange(consts.FieldGroupID)
		log.Printf("[DEBUG] Group ID has changed old=%q, new=%q", o, n)
	}

	resp, err := ReadIdentityGroup(client, gid, d.IsNewResource())
	if err != nil {
		return diag.FromErr(err)
	}

	data, err := GetGroupMember(d, resp, memberField)
	if err != nil {
		return diag.FromErr(err)
	}

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error updating field %q on Identity Group %s: err=%s", memberField, gid, err)
	}
	log.Printf("[DEBUG] Updated field %q on Identity Group %s", memberField, gid)

	d.SetId(gid)

	return nil
}

func ReadGroupMemberContextFunc(d *schema.ResourceData, client *api.Client, memberField string, setGroupName bool) diag.Diagnostics {
	id := d.Id()

	log.Printf("[DEBUG] Reading Identity Group %s with field %q", id, memberField)
	resp, err := ReadIdentityGroup(client, id, d.IsNewResource())
	if err != nil {
		if IsIdentityNotFoundError(err) {
			log.Printf("[WARN] Identity Group %s not found, removing from state", id)
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldGroupID, id); err != nil {
		return diag.FromErr(err)
	}

	if setGroupName {
		if err := d.Set(consts.FieldGroupName, resp.Data[consts.FieldName]); err != nil {
			return diag.FromErr(err)
		}
	}

	if err := SetGroupMember(d, resp, memberField); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func DeleteGroupMemberContextFunc(d *schema.ResourceData, client *api.Client, memberField string) diag.Diagnostics {
	id := d.Get(consts.FieldGroupID).(string)
	path := IdentityGroupIDPath(id)

	log.Printf("[DEBUG] Deleting Identity Group %q with field %q", memberField, id)

	resp, err := ReadIdentityGroup(client, id, false)
	if err != nil {
		if IsIdentityNotFoundError(err) {
			return nil
		}
		return diag.FromErr(err)
	}

	data, err := DeleteGroupMember(d, resp, memberField)
	if err != nil {
		return diag.FromErr(err)
	}

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error deleting Identity Group %q with field %q; err=%s", id, memberField, err)
	}
	log.Printf("[DEBUG]  Deleted Identity Group %q with field %q", memberField, id)

	return nil
}

func GetGroupMember(d *schema.ResourceData, resp *api.Secret, memberField string) (map[string]interface{}, error) {
	data := map[string]interface{}{}

	switch memberField {
	case consts.FieldMemberGroupIDs, consts.FieldMemberEntityIDs:
	default:
		return nil, fmt.Errorf("invalid value for member field")
	}
	var curIDS []interface{}
	if t, ok := resp.Data[consts.FieldType]; ok && t.(string) != consts.FieldExternal {
		if v, ok := resp.Data[memberField]; ok && v != nil {
			curIDS = v.([]interface{})
		}

		if d.Get(consts.FieldExclusive).(bool) || len(curIDS) == 0 {
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
	if d.Get(consts.FieldExclusive).(bool) {
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
		if i, ok := d.GetOk(memberField); ok && i != nil {
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
	case consts.FieldMemberGroupIDs, consts.FieldMemberEntityIDs:
	default:
		return nil, fmt.Errorf("invalid value for member field")
	}

	t, ok := resp.Data[consts.FieldType]
	if ok && t != consts.FieldExternal {
		if d.Get(consts.FieldExclusive).(bool) {
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
