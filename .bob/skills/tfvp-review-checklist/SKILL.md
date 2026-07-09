---
name: tfvp-review-checklist
description: >
  Full TFVP PR review checklist — all section-by-section checks, framework-specific
  rules, and common issues list. Activate this skill at the start of every PR review.
---

# TFVP PR Review Checklist

## Framework Detection
Identify which framework is in use before applying any checks:
- **Plugin Framework**: imports from `github.com/hashicorp/terraform-plugin-framework`
- **SDK v2**: imports from `github.com/hashicorp/terraform-plugin-sdk/v2`
- **Mixed**: migration in progress — apply both sets of rules as relevant

---

## 1. PR Structure & Documentation
- Descriptive PR title (not just a ticket number like "VAULT-1234")
- Branch naming: `JIRA-TICKET/descriptive-name`
- Milestone attached if targeting a specific release
- Changelog entry with correct category (`feature`, `improvement`, `bug`, `note`)
- Breaking changes noted in changelog
- Documentation updated (`website/docs/r/` or `website/docs/d/`)
- Vault policy changes documented
- Unreleased Vault features gated with `provider.IsAPISupported` and noted in changelog

## 2. Code Quality

### SDK v2 (Legacy)
- Field names use constants from `internal/consts`
- `d.Get()` for booleans; `d.GetOk()` for optional fields
- **NEVER** use `GetOkExists()` (deprecated)
- **NEVER** use `d.Get()` / `d.GetOk()` inside Read functions (breaks import)
- `Optional + Computed` when Vault API returns defaults
- `Required` when the user must set the value
- Integer type for durations — not strings
- No `Default` when Vault returns a default (use `Computed` instead)

### Plugin Framework (Modern)
- Typed schema attributes (`schema.StringAttribute`, `schema.Int64Attribute`, etc.)
- Implements `resource.Resource` interface: `Metadata`, `Schema`, `Create`, `Read`, `Update`, `Delete`
- State management via `req.Plan.Get()` / `resp.State.Set()`
- Validators from `stringvalidator`, `int64validator`, etc.
- `resp.Diagnostics.AddError` for all error paths
- `types.String`, `types.Int64`, `types.Bool` etc. for model fields
- `Computed` (not `Default`) for API-provided defaults
- Explicit null/unknown handling

### Common (Both Frameworks)
- Field name constants throughout
- Integer type for durations
- Proper error handling and structured log messages (`[DEBUG]`, `[INFO]`, etc.)

## 3. Resource / Data Source Structure

### SDK v2
- Backend-mounting resources use `path` field (`consts.FieldPath`)
- Non-backend-mounting resources use `mount` field (`consts.FieldMount`)
- `CreateContext`, `ReadContext`, `UpdateContext`, `DeleteContext` implemented
- **Read is called after both Create and Update**
- 404 / nil response removes resource from state
- `schema.ResourceImporter` configured for import support
- Read function does NOT use `d.Get` / `d.GetOk` (breaks import)
- Data sources have only Read — no Create / Update / Delete

### Plugin Framework
- Implements `resource.Resource` interface
- Import support via the **separate** `resource.ResourceWithImportState` interface (adds `ImportState` method)
  - Simple single-ID import: use `resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)`
  - Multi-attribute import: parse `req.ID` and call `resp.State.SetAttribute(...)` per field
- **Read is called after both Create and Update**
- 404 handled by `resp.State.RemoveResource(ctx)`
- Data sources implement `datasource.DataSource`
- Provider client wired up via `resource.ResourceWithConfigure` interface + `Configure` method
- Compile-time interface assertions present: `var _ resource.Resource = &MyResource{}`

## 4. Vault API Version Handling
- `provider.IsAPISupported()` for version-gated features
- `MountCreateContextWrapper` for minimum-version mounts
- Deprecated fields properly version-gated
- Feature flags consistent with changelog version notes

## 5. Testing
- Minimum three test steps: **Create → Update → Import**
- `ImportState: true` + `ImportStateVerify: true`
- `ImportStateVerifyIgnore` for write-only / non-returned fields
- `t.Parallel()` or `resource.ParallelTest`
- `testutil.SkipTestEnvSet(t, testutil.EnvVarSkipVaultNext)` for unreleased features
- SDK v2: `resource.Test` with `ProviderFactories`
- Plugin Framework: `resource.Test` with `ProtoV6ProviderFactories`
- All CRUD paths exercised
- Computed fields verified with `resource.TestCheckResourceAttrSet`

**Do NOT test**: Vault error message text, internal implementation details, or Vault behavior that may change between versions.

## 6. Code Reusability
- Check `helper/`, `util/`, `testutil/`, `internal/provider/` for existing helpers before writing new logic
- Path construction: use existing builders, not string concatenation
- Repeated logic (3+ occurrences) → suggest extracting to helper
- Shared test setup / teardown → suggest test helper

## 7. Security & Sensitive Data
- Sensitive fields marked `Sensitive: true` — value IS stored in state, masked in output
- **Plugin Framework only**: For secrets that must NOT persist in state at all, use `WriteOnly: true` (requires Terraform 1.11+, Framework 1.x)
  - `WriteOnly` and `Sensitive` are distinct — do not use `Sensitive` when `WriteOnly` is the right choice
  - `WriteOnly` fields: framework auto-nullifies the value; provider reads from `req.Config`, not state
- Write-only / sensitive fields never read back from Vault API response
- No hardcoded credentials or tokens
- Log messages don't leak secret values

## 8. Breaking Changes
- Behaviour changes that affect existing users are documented
- Breaking changes in changelog
- Vault policy changes noted

---

## Common Issues to Flag
| Issue | Severity |
|---|---|
| `GetOkExists()` usage | High |
| `d.Get()` in Read function | High |
| Missing Read after Create/Update | High |
| Resource not removed from state on 404 | High |
| Missing import test step | High |
| Hardcoded credentials | High |
| Missing `ImportStateVerifyIgnore` for write-only fields | Medium |
| Wrong `Optional`/`Computed`/`Required` combo | Medium |
| `Default` used instead of `Computed` for API defaults | Medium |
| Missing version check for new Vault feature | Medium |
| Missing changelog entry | Medium |
| String type used for durations | Medium |
| Magic strings (no constant) | Low |
| Missing or incomplete documentation | Low |
| Incorrect branch naming | Low |
| Missing milestone | Low |
