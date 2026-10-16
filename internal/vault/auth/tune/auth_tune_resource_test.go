// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package tune

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestTuneConfigOmitsUnsetFields(t *testing.T) {
	t.Parallel()

	plan := configuredModel()
	plan.DefaultLeaseTTL = types.StringValue("12h")

	cfg, diags := tuneConfig(context.Background(), &plan, &authTuneModel{}, false)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if cfg.DefaultLeaseTTL == nil || *cfg.DefaultLeaseTTL != "12h" {
		t.Fatalf("default_lease_ttl = %v, want 12h", cfg.DefaultLeaseTTL)
	}
	if cfg.MaxLeaseTTL != nil || cfg.TokenType != nil || cfg.ListingVisibility != nil || cfg.PluginVersion != nil {
		t.Fatalf("unset strings were included: %#v", cfg)
	}
	if cfg.AuditNonHMACRequestKeys != nil || cfg.PassthroughRequestHeaders != nil || cfg.AllowedResponseHeaders != nil || cfg.AuditNonHMACResponseKeys != nil {
		t.Fatalf("unset lists were included: %#v", cfg)
	}
	if cfg.UserLockoutConfig != nil {
		t.Fatal("lockout config was included")
	}
}

func TestTuneConfigClearsRemovedFields(t *testing.T) {
	t.Parallel()

	prior := configuredModel()
	prior.TokenType = types.StringValue("batch")
	prior.DefaultLeaseTTL = types.StringValue("12h")
	prior.AuditNonHMACRequestKeys = types.ListValueMust(types.StringType, []attr.Value{types.StringValue("key1")})

	plan := configuredModel()
	plan.DefaultLeaseTTL = types.StringValue("12h")

	cfg, diags := tuneConfig(context.Background(), &plan, &prior, true)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if cfg.TokenType == nil || *cfg.TokenType != "" {
		t.Fatalf("token_type = %v, want empty string", cfg.TokenType)
	}
	if cfg.DefaultLeaseTTL == nil || *cfg.DefaultLeaseTTL != "12h" {
		t.Fatalf("default_lease_ttl = %v, want 12h", cfg.DefaultLeaseTTL)
	}
	if cfg.AuditNonHMACRequestKeys == nil || len(*cfg.AuditNonHMACRequestKeys) != 1 || (*cfg.AuditNonHMACRequestKeys)[0] != "" {
		t.Fatalf("audit keys = %v, want clear sentinel", cfg.AuditNonHMACRequestKeys)
	}
	if cfg.ListingVisibility != nil {
		t.Fatal("listing_visibility should stay omitted")
	}
}

func TestTuneConfigResetsRemovedLockout(t *testing.T) {
	t.Parallel()

	prior := configuredModel()
	prior.UserLockoutConfig = &userLockoutModel{
		LockoutThreshold:    types.StringValue("5"),
		LockoutDuration:     types.StringValue("10m"),
		LockoutCounterReset: types.StringNull(),
		LockoutDisable:      types.BoolValue(true),
	}
	plan := configuredModel()

	cfg, diags := tuneConfig(context.Background(), &plan, &prior, true)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if cfg.UserLockoutConfig == nil {
		t.Fatal("expected lockout reset")
	}
	if cfg.UserLockoutConfig.LockoutThreshold == nil || *cfg.UserLockoutConfig.LockoutThreshold != "0" {
		t.Fatalf("threshold = %v", cfg.UserLockoutConfig.LockoutThreshold)
	}
	if cfg.UserLockoutConfig.LockoutDuration == nil || *cfg.UserLockoutConfig.LockoutDuration != "0s" {
		t.Fatalf("duration = %v", cfg.UserLockoutConfig.LockoutDuration)
	}
	if cfg.UserLockoutConfig.DisableLockout == nil || *cfg.UserLockoutConfig.DisableLockout {
		t.Fatalf("disable = %v, want false", cfg.UserLockoutConfig.DisableLockout)
	}
	if cfg.UserLockoutConfig.LockoutCounterResetDuration != nil {
		t.Fatal("unset counter reset should be omitted")
	}
}

func TestRefreshLeavesUnsetFieldsNull(t *testing.T) {
	t.Parallel()

	model := configuredModel()
	model.DefaultLeaseTTL = types.StringValue("200s")
	model.refresh(context.Background(), tuneSnapshot{
		defaultLeaseTTL:          "3m20s",
		defaultLeaseTTLPresent:   true,
		tokenType:                "default-service",
		tokenTypePresent:         true,
		listingVisibility:        "hidden",
		listingVisibilityPresent: true,
		maxLeaseTTL:              "768h",
		maxLeaseTTLPresent:       true,
	})

	if model.DefaultLeaseTTL.ValueString() != "200s" {
		t.Fatalf("ttl = %s, want the configured 200s", model.DefaultLeaseTTL.ValueString())
	}
	if !model.TokenType.IsNull() {
		t.Fatalf("token_type = %s, want null", model.TokenType.ValueString())
	}
	if !model.ListingVisibility.IsNull() || !model.MaxLeaseTTL.IsNull() {
		t.Fatal("API defaults were written into unset fields")
	}
}

func TestRefreshReplacesDriftedDuration(t *testing.T) {
	t.Parallel()

	model := configuredModel()
	model.DefaultLeaseTTL = types.StringValue("200s")
	model.refresh(context.Background(), tuneSnapshot{
		defaultLeaseTTL:        "5m",
		defaultLeaseTTLPresent: true,
	})

	if model.DefaultLeaseTTL.ValueString() != "5m" {
		t.Fatalf("ttl = %s, want 5m", model.DefaultLeaseTTL.ValueString())
	}
}

func TestParseTuneDurationAndLockout(t *testing.T) {
	t.Parallel()

	snap := parseTune(map[string]interface{}{
		"default_lease_ttl":                   json.Number("200"),
		"max_lease_ttl":                       float64(3600),
		"token_type":                          "batch",
		"audit_non_hmac_request_keys":         []interface{}{"key1", ""},
		"user_lockout_threshold":              json.Number("5"),
		"user_lockout_duration":               json.Number("600"),
		"user_lockout_counter_reset_duration": json.Number("60"),
		"user_lockout_disable":                true,
	})

	if !snap.defaultLeaseTTLPresent || snap.defaultLeaseTTL != "3m20s" {
		t.Fatalf("default ttl = %q present=%v", snap.defaultLeaseTTL, snap.defaultLeaseTTLPresent)
	}
	if snap.maxLeaseTTL != "1h" {
		t.Fatalf("max ttl = %q", snap.maxLeaseTTL)
	}
	if snap.tokenType != "batch" {
		t.Fatalf("token_type = %q", snap.tokenType)
	}
	if !snap.lockoutPresent || snap.lockout.threshold != "5" || snap.lockout.duration != "10m" || !snap.lockout.disable {
		t.Fatalf("lockout = %#v", snap.lockout)
	}
	if len(normalizeList(snap.auditNonHMACRequestKeys)) != 1 || snap.auditNonHMACRequestKeys[0] != "key1" {
		t.Fatalf("audit keys = %#v", snap.auditNonHMACRequestKeys)
	}
}

func configuredModel() authTuneModel {
	return authTuneModel{
		Path:                      types.StringValue("userpass"),
		DefaultLeaseTTL:           types.StringNull(),
		MaxLeaseTTL:               types.StringNull(),
		ListingVisibility:         types.StringNull(),
		TokenType:                 types.StringNull(),
		PluginVersion:             types.StringNull(),
		AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
		AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
		PassthroughRequestHeaders: types.ListNull(types.StringType),
		AllowedResponseHeaders:    types.ListNull(types.StringType),
	}
}
