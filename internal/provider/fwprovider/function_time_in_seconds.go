// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ function.Function = &TimeInSecondsFunction{}

// TimeInSecondsFunction parses a Vault duration string and returns a whole number of seconds.
// Parsing uses parseutil.ParseDurationSecond, which accepts Go duration units, a "d" suffix, and bare integers as seconds.
type TimeInSecondsFunction struct{}

// NewTimeInSecondsFunction returns the provider function registered as "time_in_seconds".
func NewTimeInSecondsFunction() function.Function {
	return &TimeInSecondsFunction{}
}

func (f *TimeInSecondsFunction) Metadata(ctx context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "time_in_seconds"
}

func (f *TimeInSecondsFunction) Definition(ctx context.Context, req function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:     "Convert a Vault duration string to an integer number of seconds",
		Description: "Given a Vault duration string (Go duration units, a \"d\" suffix, or a bare integer number of seconds), returns the duration as an integer number of seconds. Negative durations and durations that are not a whole number of seconds are errors.",

		Parameters: []function.Parameter{
			function.StringParameter{
				Name:        "duration",
				Description: "Vault duration string to parse",
			},
		},
		Return: function.Int64Return{},
	}
}

func (f *TimeInSecondsFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var input string

	resp.Error = req.Arguments.Get(ctx, &input)
	if resp.Error != nil {
		return
	}

	if input == "" {
		resp.Error = function.NewArgumentFuncError(0, "Error parsing duration string: duration must not be empty")
		return
	}

	duration, err := parseutil.ParseDurationSecond(input)
	if err != nil {
		// Intentionally not including the parse error in the return diagnostic, as the message is based on a Go-specific
		// reference time that may be unfamiliar to practitioners.
		tflog.Error(ctx, fmt.Sprintf("failed to parse duration string, underlying error: %s", err.Error()))

		resp.Error = function.NewArgumentFuncError(0, fmt.Sprintf("Error parsing duration string: %q is not a valid duration string", input))
		return
	}

	if duration < 0 {
		resp.Error = function.NewArgumentFuncError(0, fmt.Sprintf("Error parsing duration string: %q must not be negative", input))
		return
	}

	if duration%time.Second != 0 {
		resp.Error = function.NewArgumentFuncError(0, fmt.Sprintf("Error parsing duration string: %q must be a whole number of seconds", input))
		return
	}

	seconds := int64(duration / time.Second)
	resp.Error = resp.Result.Set(ctx, &seconds)
}
