// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helper

import (
	"encoding/json"
	"time"

	"github.com/hashicorp/terraform-provider-vault/util"
)

func FlattenVaultDuration(d interface{}) string {
	if d == nil {
		return time.Duration(0).String()
	}

	switch d.(type) {
	case int:
		return util.ShortDur(time.Duration(d.(int)) * time.Second)
	case int64:
		return util.ShortDur(time.Duration(d.(int64)) * time.Second)
	case json.Number:
		if i, err := d.(json.Number).Int64(); err == nil {
			return util.ShortDur(time.Duration(i) * time.Second)
		}
	}

	return time.Duration(0).String()
}
