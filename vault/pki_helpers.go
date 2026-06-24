// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func setDefaultStringAllowEmpty(d *schema.ResourceData, data map[string]interface{}, key string, defaultVal string) {
	if v, ok := d.GetOk(key); ok {
		data[key] = v
	} else {
		data[key] = defaultVal
	}
}

func setDefaultStringEmptyNotAllowed(d *schema.ResourceData, data map[string]interface{}, key string, defaultVal string) {
	if v, ok := d.GetOk(key); ok && v.(string) != "" {
		data[key] = v
	} else {
		data[key] = defaultVal
	}
}
