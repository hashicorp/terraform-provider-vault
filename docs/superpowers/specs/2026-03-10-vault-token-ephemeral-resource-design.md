# Design: `vault_token` Ephemeral Resource

## Purpose

Replace the manual workflow of `vault token create -policy nomad -period 72h -orphan` followed by storing in a secrets manager. This ephemeral resource allows Terraform to create a Vault token in a single run without persisting it in state.

## Approach

Direct port of the existing `vault_token` resource to the Terraform Plugin Framework ephemeral resource pattern. Uses the typed `api.TokenCreateRequest` and `client.Auth().Token().Create()` / `.CreateWithRole()` APIs. No `Close()` method — tokens persist until TTL/period expires naturally.

## Schema

### Input Fields (all Optional)

| Field | Type | Description |
|-------|------|-------------|
| `role_name` | String | Token role name; changes API path to `auth/token/create/{role}` |
| `policies` | Set[String] | List of policies |
| `no_parent` | Bool | Create orphan token |
| `no_default_policy` | Bool | Disable default policy |
| `renewable` | Bool | Allow token renewal |
| `ttl` | String | TTL period (e.g. "60s", "72h") |
| `explicit_max_ttl` | String | Explicit max TTL |
| `period` | String | Period for periodic tokens |
| `display_name` | String | Display name |
| `num_uses` | Int64 | Number of allowed uses |
| `wrapping_ttl` | String | Wrapping TTL |
| `metadata` | Map[String] | Token metadata |
| `namespace` | String | Vault Enterprise namespace (from base) |
| `mount_id` | String | Dependency anchor (from base) |

### Output Fields (Computed)

| Field | Type | Sensitive |
|-------|------|-----------|
| `client_token` | String | Yes |
| `wrapped_token` | String | Yes |
| `wrapping_accessor` | String | Yes |
| `lease_duration` | Int64 | No |
| `lease_started` | String | No |

### Excluded Fields

`renew_min_lease` and `renew_increment` from the existing resource are excluded — they are lifecycle management fields that don't apply to ephemeral resources (no Read/renewal cycle).

## Implementation

### File Location

`/internal/vault/auth/ephemeral/token.go` — under the auth directory because the API path is `auth/token/create`, consistent with the directory placement convention (auth API paths live under `/internal/vault/auth/`).

### Package

`ephemeralauth` (same as `approle_auth_backend_role_secret_id.go`)

### Structs

- `TokenEphemeralResource` — embeds `base.EphemeralResourceWithConfigure`
- `TokenEphemeralModel` — embeds `base.BaseModelEphemeral`, all schema fields
- No API model struct — uses typed `api.TokenCreateRequest` and reads from `resp.Auth` / `resp.WrapInfo` directly

### Open() Method Logic

1. Read config into model
2. Get Vault client via `client.GetClient()`
3. Build `api.TokenCreateRequest` from model fields (same field mapping as existing resource's `tokenCreate`)
4. If `wrapping_ttl` is set, clone client and set wrapping lookup func (same pattern as existing resource)
5. If `role_name` is set: `client.Auth().Token().CreateWithRole(req, role)`, otherwise: `client.Auth().Token().Create(req)`
6. If wrapped: set `wrapped_token` and `wrapping_accessor` from `resp.WrapInfo`; otherwise set `client_token` from `resp.Auth.ClientToken`
7. Set `lease_duration` and `lease_started` from response
8. Set result

### No Close() Method

Token persists until TTL/period expires. Consistent with the majority of existing ephemeral resources.

### Registration

Add `ephemeralauth.NewTokenEphemeralResource` to `EphemeralResources()` in `/internal/provider/fwprovider/provider.go`.

### Metadata Name

`vault_token` (i.e. `req.ProviderTypeName + "_token"`)

## Tests

### File

`/internal/vault/auth/ephemeral/token_test.go` (package `ephemeralauth_test`)

### Pattern

Echo provider to capture ephemeral values, with `ProtoV5ProviderFactories` for vault provider and `ProtoV6ProviderFactories` for echo provider. Consistent with existing ephemeral resource tests.

### Test Cases

1. **`TestAccTokenEphemeral_basic`** — Create a policy, open ephemeral token with that policy and a TTL. Assert `client_token` is set.

2. **`TestAccTokenEphemeral_full`** — All input fields: `policies`, `no_parent`, `no_default_policy`, `renewable`, `ttl`, `explicit_max_ttl`, `display_name`, `num_uses`, `metadata`. Assert all computed outputs are set and input values round-trip through echo provider.

3. **`TestAccTokenEphemeral_withRole`** — Create a `vault_token_auth_backend_role`, open ephemeral token with `role_name` set. Assert `client_token` is returned. Exercises `CreateWithRole` code path.

4. **`TestAccTokenEphemeral_wrapped`** — Set `wrapping_ttl`, assert `wrapped_token` and `wrapping_accessor` are set and `client_token` is not.

### Coverage vs Existing Resource Tests

| Resource Test | Ephemeral Equivalent | Notes |
|---|---|---|
| `TestResourceToken_basic` | `TestAccTokenEphemeral_basic` | Equivalent |
| `TestResourceToken_full` | `TestAccTokenEphemeral_full` | Equivalent |
| `TestResourceToken_import` | N/A | Ephemeral resources can't be imported |
| `TestResourceToken_lookup` | N/A | No state to look up |
| `TestResourceToken_expire` | N/A | No lifecycle to manage |
| `TestResourceToken_renew` | N/A | No renewal in ephemeral |
| N/A | `TestAccTokenEphemeral_withRole` | Exercises CreateWithRole path |
| N/A | `TestAccTokenEphemeral_wrapped` | Exercises wrapping path |

## Files Changed

| File | Change |
|---|---|
| `internal/vault/auth/ephemeral/token.go` | New — implementation (~200-250 lines) |
| `internal/vault/auth/ephemeral/token_test.go` | New — 4 acceptance tests (~150-200 lines) |
| `internal/provider/fwprovider/provider.go` | Edit — 1 line registration |

No new constants needed — all field names exist in `internal/consts/consts.go`.
