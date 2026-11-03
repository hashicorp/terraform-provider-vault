// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ function.Function = &TimeInSecondsFunction{}

// TimeInSecondsFunction parses a Go duration string and returns the duration in seconds.
// Parsing uses time.ParseDuration, the same rules as hashicorp/time's duration_parse.
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
		Summary:     "Convert a [Go duration string](https://pkg.go.dev/time#ParseDuration) to seconds",
		Description: "Given a [Go duration string](https://pkg.go.dev/time#ParseDuration), returns the duration as a number of seconds.",

		Parameters: []function.Parameter{
			function.StringParameter{
				Name:        "duration",
				Description: "Go time package duration string to parse",
			},
		},
		Return: function.Float64Return{},
	}
}

func (f *TimeInSecondsFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var input string

	resp.Error = req.Arguments.Get(ctx, &input)
	if resp.Error != nil {
		return
	}

	duration, err := time.ParseDuration(input)
	if err != nil {
		// Intentionally not including the Go parse error in the return diagnostic, as the message is based on a Go-specific
		// reference time that may be unfamiliar to practitioners
		tflog.Error(ctx, fmt.Sprintf("failed to parse duration string, underlying time.Duration error: %s", err.Error()))

		resp.Error = function.NewArgumentFuncError(0, fmt.Sprintf("Error parsing duration string: %q is not a valid duration string", input))
		return
	}

	seconds := duration.Seconds()
	resp.Error = resp.Result.Set(ctx, &seconds)
}
