// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
)

// TestMuxSchemaConsistency verifies that the SDKv2 and plugin-framework
// provider schemas are identical, which the tf5muxserver requires. This
// reproduces the "differing provider schema implementations" error offline,
// without needing terraform or a live Vault.
func TestMuxSchemaConsistency(t *testing.T) {
	ctx := context.Background()
	factory, _, err := ProtoV5ProviderServerFactory(ctx)
	if err != nil {
		t.Fatalf("ProtoV5ProviderServerFactory() error: %v", err)
	}

	srv := factory()
	resp, err := srv.GetProviderSchema(ctx, &tfprotov5.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("GetProviderSchema() error: %v", err)
	}

	if len(resp.Diagnostics) > 0 {
		for _, d := range resp.Diagnostics {
			t.Errorf("schema diagnostic: severity=%v summary=%q detail=%q",
				d.Severity, d.Summary, d.Detail)
		}
		t.Fatal("muxed provider reported schema diagnostics (schemas differ across providers)")
	}
}
