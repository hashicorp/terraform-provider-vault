// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestDataJSONMarshaling demonstrates the bug where marshaling data.Data (types.Map)
// produces incorrect output compared to marshaling the raw data (map[string]interface{})
func TestDataJSONMarshaling(t *testing.T) {
	ctx := context.Background()

	// Simulate data from Vault with nested objects
	vaultData := map[string]interface{}{
		"simple_string": "value1",
		"nested_object": map[string]interface{}{
			"cluster": map[string]interface{}{
				"id":     "test-id",
				"secret": "test-secret",
			},
		},
	}

	// Test Case 1: Marshal raw data directly (correct approach)
	jsonDataCorrect, err := json.Marshal(vaultData)
	if err != nil {
		t.Fatalf("Failed to marshal raw data: %v", err)
	}

	var decodedCorrect map[string]interface{}
	err = json.Unmarshal(jsonDataCorrect, &decodedCorrect)
	if err != nil {
		t.Fatalf("Failed to unmarshal correct JSON: %v", err)
	}

	// Verify nested access works
	if nested, ok := decodedCorrect["nested_object"].(map[string]interface{}); !ok {
		t.Error("Correct approach: nested_object is not a map")
	} else if cluster, ok := nested["cluster"].(map[string]interface{}); !ok {
		t.Error("Correct approach: cluster is not a map")
	} else if id, ok := cluster["id"].(string); !ok || id != "test-id" {
		t.Errorf("Correct approach: cluster.id = %v, want 'test-id'", id)
	}

	t.Logf("✓ Correct JSON: %s", string(jsonDataCorrect))

	// Test Case 2: Convert to types.Map with StringType, then marshal (buggy approach)
	// This will fail for nested objects because StringType can't hold maps
	typesMap, diag := types.MapValueFrom(ctx, types.StringType, vaultData)
	if diag.HasError() {
		t.Logf("✓ BUG CONFIRMED: types.MapValueFrom fails with nested objects")
		t.Logf("  Diagnostics: %v", diag)

		// This is the expected error that proves the bug
		for _, d := range diag.Errors() {
			t.Logf("  Error: %s - %s", d.Summary(), d.Detail())
		}

		return // Test passes by confirming the bug exists
	}

	// If we got here (shouldn't with nested objects), marshal the types.Map
	jsonDataWrong, err := json.Marshal(typesMap)
	if err != nil {
		t.Fatalf("Failed to marshal types.Map: %v", err)
	}

	t.Logf("Wrong JSON (if it even worked): %s", string(jsonDataWrong))
	t.Error("Expected types.MapValueFrom to fail with nested objects, but it succeeded")
}

// TestDataJSONMarshalingFlatStructure tests that flat structures work with both approaches
func TestDataJSONMarshalingFlatStructure(t *testing.T) {
	ctx := context.Background()

	// Flat data structure (only string values)
	vaultData := map[string]interface{}{
		"password": "pass123",
		"username": "user456",
	}

	// Both approaches should work for flat structures
	jsonDataCorrect, err := json.Marshal(vaultData)
	if err != nil {
		t.Fatalf("Failed to marshal raw data: %v", err)
	}

	typesMap, diag := types.MapValueFrom(ctx, types.StringType, vaultData)
	if diag.HasError() {
		t.Fatalf("types.MapValueFrom failed for flat structure: %v", diag)
	}

	jsonDataFromTypes, err := json.Marshal(typesMap)
	if err != nil {
		t.Fatalf("Failed to marshal types.Map: %v", err)
	}

	t.Logf("Flat structure - Raw data JSON: %s", string(jsonDataCorrect))
	t.Logf("Flat structure - types.Map JSON: %s", string(jsonDataFromTypes))

	// Note: The JSON from types.Map will be different (internal representation)
	// but both should be valid JSON
	var decoded1, decoded2 map[string]interface{}
	if err := json.Unmarshal(jsonDataCorrect, &decoded1); err != nil {
		t.Errorf("Failed to unmarshal correct JSON: %v", err)
	}
	if err := json.Unmarshal(jsonDataFromTypes, &decoded2); err != nil {
		t.Errorf("Failed to unmarshal types.Map JSON: %v", err)
	}

	// The raw data approach produces the expected JSON structure
	if decoded1["password"] != "pass123" {
		t.Errorf("Raw data JSON: password = %v, want 'pass123'", decoded1["password"])
	}
}
