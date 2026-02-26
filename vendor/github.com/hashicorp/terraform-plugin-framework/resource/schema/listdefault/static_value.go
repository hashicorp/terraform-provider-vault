// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package listdefault

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/defaults"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// StaticValue returns a static list value default handler.
//
// Use StaticValue if a static default value for a list should be set.
func StaticValue(defaultVal types.List) defaults.List {
	return staticValueDefault{
		defaultVal: defaultVal,
	}
}

// staticValueDefault is static value default handler that
// sets a value on a list attribute.
type staticValueDefault struct {
	defaultVal types.List
}

// Description returns a human-readable description of the default value handler.
func (d staticValueDefault) Description(_ context.Context) string {
	return fmt.Sprintf("value defaults to %v", d.defaultVal)
}

// MarkdownDescription returns a markdown description of the default value handler.
func (d staticValueDefault) MarkdownDescription(_ context.Context) string {
	return fmt.Sprintf("value defaults to `%v`", d.defaultVal)
}

// DefaultList implements the static default value logic.
func (d staticValueDefault) DefaultList(ctx context.Context, req defaults.ListRequest, resp *defaults.ListResponse) {
	resp.PlanValue = d.defaultVal
}
