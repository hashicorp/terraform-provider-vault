// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package int64default

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/defaults"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// StaticInt64 returns a static int64 value default handler.
//
// Use StaticInt64 if a static default value for a int64 should be set.
func StaticInt64(defaultVal int64) defaults.Int64 {
	return staticInt64Default{
		defaultVal: defaultVal,
	}
}

// staticInt64Default is static value default handler that
// sets a value on an int64 attribute.
type staticInt64Default struct {
	defaultVal int64
}

// Description returns a human-readable description of the default value handler.
func (d staticInt64Default) Description(_ context.Context) string {
	return fmt.Sprintf("value defaults to %d", d.defaultVal)
}

// MarkdownDescription returns a markdown description of the default value handler.
func (d staticInt64Default) MarkdownDescription(_ context.Context) string {
	return fmt.Sprintf("value defaults to `%d`", d.defaultVal)
}

// DefaultInt64 implements the static default value logic.
func (d staticInt64Default) DefaultInt64(_ context.Context, req defaults.Int64Request, resp *defaults.Int64Response) {
	resp.PlanValue = types.Int64Value(d.defaultVal)
}
