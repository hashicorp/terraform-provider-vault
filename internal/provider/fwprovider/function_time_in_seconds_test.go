// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestTimeInSecondsFunctionMetadata(t *testing.T) {
	t.Parallel()

	var resp function.MetadataResponse
	NewTimeInSecondsFunction().Metadata(context.Background(), function.MetadataRequest{}, &resp)
	if resp.Name != "time_in_seconds" {
		t.Fatalf("Name = %q, want %q", resp.Name, "time_in_seconds")
	}
}

func TestTimeInSecondsFunctionValid(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"1h", "60m", "3600s", "3600000ms", "3600000000us", "3600000000000ns"} {
		t.Run(input, func(t *testing.T) {
			t.Parallel()

			resp := runTimeInSecondsFunction(t, input)
			if resp.Error != nil {
				t.Fatalf("unexpected error: %s", resp.Error)
			}

			got, ok := resp.Result.Value().(types.Float64)
			if !ok {
				t.Fatalf("result type = %T, want types.Float64", resp.Result.Value())
			}
			if got.ValueFloat64() != 3600 {
				t.Fatalf("seconds = %v, want 3600", got.ValueFloat64())
			}
		})
	}
}

func TestTimeInSecondsFunctionInvalid(t *testing.T) {
	t.Parallel()

	resp := runTimeInSecondsFunction(t, "abcdef")
	if resp.Error == nil {
		t.Fatal("expected an error")
	}
	const want = `Error parsing duration string: "abcdef" is not a valid duration string`
	if resp.Error.Error() != want {
		t.Fatalf("error = %q, want %q", resp.Error.Error(), want)
	}
	if resp.Error.FunctionArgument == nil || *resp.Error.FunctionArgument != 0 {
		t.Fatalf("FunctionArgument = %v, want 0", resp.Error.FunctionArgument)
	}
}

func runTimeInSecondsFunction(t *testing.T, input string) function.RunResponse {
	t.Helper()

	resp := function.RunResponse{
		Result: function.NewResultData(types.Float64Unknown()),
	}
	NewTimeInSecondsFunction().Run(context.Background(), function.RunRequest{
		Arguments: function.NewArgumentsData([]attr.Value{types.StringValue(input)}),
	}, &resp)
	return resp
}
