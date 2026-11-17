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

func TestTuneConfigResetsRemovedTTLs(t *testing.T) {
	t.Parallel()

	prior := configuredModel()
	prior.DefaultLeaseTTL = types.StringValue("12h")
	prior.MaxLeaseTTL = types.StringValue("24h")
	plan := configuredModel()

	cfg, diags := tuneConfig(context.Background(), &plan, &prior, true)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if cfg.DefaultLeaseTTL == nil || *cfg.DefaultLeaseTTL != "system" {
		t.Fatalf("default_lease_ttl = %v, want system", cfg.DefaultLeaseTTL)
	}
	if cfg.MaxLeaseTTL == nil || *cfg.MaxLeaseTTL != "system" {
		t.Fatalf("max_lease_ttl = %v, want system", cfg.MaxLeaseTTL)
	}
}

func TestTuneConfigDestroyResetsTTLs(t *testing.T) {
	t.Parallel()

	prior := configuredModel()
	prior.DefaultLeaseTTL = types.StringValue("12h")
	prior.MaxLeaseTTL = types.StringValue("24h")

	cfg, diags := tuneConfig(context.Background(), &authTuneModel{}, &prior, true)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if cfg.DefaultLeaseTTL == nil || *cfg.DefaultLeaseTTL != "system" {
		t.Fatalf("default_lease_ttl = %v, want system", cfg.DefaultLeaseTTL)
	}
	if cfg.MaxLeaseTTL == nil || *cfg.MaxLeaseTTL != "system" {
		t.Fatalf("max_lease_ttl = %v, want system", cfg.MaxLeaseTTL)
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

func TestTuneConfigSendsPluginVersion(t *testing.T) {
	t.Parallel()

	plan := configuredModel()
	plan.PluginVersion = types.StringValue("v1.2.3")

	cfg, diags := tuneConfig(context.Background(), &plan, &authTuneModel{}, false)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if cfg.PluginVersion == nil || *cfg.PluginVersion != "v1.2.3" {
		t.Fatalf("plugin_version = %v, want v1.2.3", cfg.PluginVersion)
	}
}

func TestRefreshRecordsExternalClear(t *testing.T) {
	t.Parallel()

	model := configuredModel()
	model.ListingVisibility = types.StringValue("unauth")
	model.DefaultLeaseTTL = types.StringValue("12h")
	model.refresh(context.Background(), tuneSnapshot{
		listingVisibility:        "",
		listingVisibilityPresent: true,
		defaultLeaseTTL:          "",
		defaultLeaseTTLPresent:   true,
	})

	if !model.ListingVisibility.IsNull() {
		t.Fatalf("listing_visibility = %#v, want null", model.ListingVisibility)
	}
	if !model.DefaultLeaseTTL.IsNull() {
		t.Fatalf("default_lease_ttl = %#v, want null", model.DefaultLeaseTTL)
	}
}

func TestImportedModelReadsNonDefaultTune(t *testing.T) {
	t.Parallel()

	snap := parseTune(map[string]interface{}{
		"default_lease_ttl":                   json.Number("600"),
		"max_lease_ttl":                       json.Number("1200"),
		"token_type":                          "batch",
		"listing_visibility":                  "unauth",
		"audit_non_hmac_request_keys":         []interface{}{"request-key"},
		"user_lockout_threshold":              json.Number("5"),
		"user_lockout_duration":               json.Number("600"),
		"user_lockout_counter_reset_duration": json.Number("900"),
		"user_lockout_disable":                true,
	})
	model := snap.importedModel("userpass", "")

	if model.Path.ValueString() != "userpass" || !model.Namespace.IsNull() {
		t.Fatalf("identity = path %q namespace null %v", model.Path.ValueString(), model.Namespace.IsNull())
	}
	if model.DefaultLeaseTTL.ValueString() != "10m" || model.MaxLeaseTTL.ValueString() != "20m" {
		t.Fatalf("ttls = %s %s", model.DefaultLeaseTTL.ValueString(), model.MaxLeaseTTL.ValueString())
	}
	if model.TokenType.ValueString() != "batch" || model.ListingVisibility.ValueString() != "unauth" {
		t.Fatalf("token_type = %s listing = %s", model.TokenType.ValueString(), model.ListingVisibility.ValueString())
	}
	if model.UserLockoutConfig == nil || !model.UserLockoutConfig.LockoutDisable.ValueBool() {
		t.Fatal("expected lockout disable")
	}
	if model.UserLockoutConfig.LockoutThreshold.ValueString() != "5" || model.UserLockoutConfig.LockoutDuration.ValueString() != "10m" || model.UserLockoutConfig.LockoutCounterReset.ValueString() != "15m" {
		t.Fatalf("lockout = %#v", model.UserLockoutConfig)
	}
	if !model.PluginVersion.IsNull() {
		t.Fatal("empty plugin_version should stay unset")
	}
}

func TestImportedModelOmitsDefaultLockout(t *testing.T) {
	t.Parallel()

	snap := tuneSnapshot{
		lockoutPresent: true,
		lockout: lockoutSnapshot{
			threshold:        "0",
			thresholdPresent: true,
			duration:         "0s",
			durationPresent:  true,
			disable:          false,
			disablePresent:   true,
		},
	}
	if snap.importedModel("userpass", "admin").UserLockoutConfig != nil {
		t.Fatal("default lockout should stay unset")
	}
}

func TestAuthTuneImportPath(t *testing.T) {
	t.Parallel()

	path, err := authTuneImportPath("auth/userpass/")
	if err != nil || path != "userpass" {
		t.Fatalf("path = %q err = %v", path, err)
	}
	if _, err := authTuneImportPath("  "); err == nil {
		t.Fatal("expected empty identifier error")
	}
	if _, err := authTuneImportPath("auth/"); err == nil {
		t.Fatal("expected empty identifier error")
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
