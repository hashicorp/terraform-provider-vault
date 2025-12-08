// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package automatedrotationutil

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/vault/api"
)

var AutomatedRotationFields = []string{
	consts.FieldRotationSchedule,
	consts.FieldRotationPeriod,
	consts.FieldRotationWindow,
	consts.FieldDisableAutomatedRotation,
}

func ParseAutomatedRotationFields(d *schema.ResourceData, data map[string]interface{}) {
	for _, field := range AutomatedRotationFields {
		data[field] = d.Get(field)
	}
}

func PopulateAutomatedRotationFields(d *schema.ResourceData, resp *api.Secret, path string) error {
	for _, k := range AutomatedRotationFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for mount at %q: %q", k, path, err)
			}
		}
	}

	return nil
}

func ParseAutomatedRotationFieldsWithFieldPrefix(d *schema.ResourceData, data map[string]interface{}, prefix string) {
	for _, field := range AutomatedRotationFields {
		data[field] = d.Get(prefix + field)
	}
}

func GetAutomatedRotationFieldsFromResponse(resp *api.Secret, result map[string]interface{}) {
	for _, k := range AutomatedRotationFields {
		if v, ok := resp.Data[k]; ok {
			result[k] = v
		}
	}
}
