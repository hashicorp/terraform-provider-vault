# Working Preferences and Standards

## Code Style

### Go conventions
- Format all Go code with `gofmt -s`. The CI gate is `make fmtcheck`; run `make fmt` to auto-fix.
- Run `go vet` (`make vet`) before opening a PR.
- Go version is pinned in `.go-version` (currently `1.26.4`). Do not upgrade without explicit intent.

### Field names
- **Always use constants** for schema field names. Add new constants to [`internal/consts/consts.go`](../../internal/consts/consts.go). Resource-local constants are fine for fields that are truly unique to one resource.

### Schema patterns
- Use `d.Get()` or `d.GetOk()` — never `d.GetOkExists()` (deprecated).
- `d.Get` in Read functions is only acceptable for sensitive fields Vault redacts on read (e.g. passwords). For all other fields, read from Vault's API response.
- Duration fields: always integer (seconds), never string.
- If Vault returns a default value for a field → `Computed: true` (no `Default`). Exception: boolean fields defaulting to `true` → use `Default: true`.
- When Vault returns a value even when not explicitly set: use `Optional + Computed`.
- Always perform a READ after WRITE in both Create and Update operations.
- 404 / not-found responses in Read should remove the resource from state (call `d.SetId("")`).
- Log messages must be prefixed with a log level: `log.Printf("[DEBUG] ...")`.

### SDK choice
- Most existing resources use `terraform-plugin-sdk/v2` (lives in `vault/`).
- New resources should prefer `terraform-plugin-framework` where feasible (lives in `internal/framework/`).
- Do not mix SDK patterns within a single resource.

---

## Testing Standards

### Unit tests
- Every new or changed resource/data source must have unit tests.
- Run with `make test`. No live Vault required.
- Tag: tests use `-tags testonly`.

### Acceptance tests
- Required for all user-facing changes, covering the "sunny path" for all changed fields.
- Require a live Vault instance (`VAULT_ADDR`, `VAULT_TOKEN` env vars).
- Run with `make testacc TESTARGS='-run=TestAccXXX'`.
- Enterprise-only tests: `make testacc-ent`.
- PR template requires pasting acceptance test output before requesting review.
- Version-dependent tests must use `provider.IsAPISupported` guards.

---

## PR & Commit Standards

### Branch naming
```
VAULT-XXXX/short-description
```
For multi-PR feature work:
```
VAULT-XXXX/subsystem/feature-name
```

### PR checklist (from official TFVP PR checklist)
- [ ] Descriptive PR title (e.g. `VAULT-1234 Add foo field to bar resource`)
- [ ] CHANGELOG entry for any user-facing change
- [ ] Vault policy impact noted in CHANGELOG if the Vault endpoint being called changes
- [ ] Documentation updated (including `website/vault.erb` index for net-new docs)
- [ ] Breaking changes noted in CHANGELOG
- [ ] Version-dependent fields/resources gated with `provider.IsAPISupported`
- [ ] Unit and/or acceptance tests written/updated
- [ ] Read-after-write in Create and Update
- [ ] Import support in Read (`d.Get` in Read discouraged; prefer extracting from resource ID)
- [ ] 404 in Read removes resource from state
- [ ] Log messages prefixed with log level
- [ ] CI green before requesting review
- [ ] PR milestoned to target release version (e.g. `3.13.0`)

### Requesting review
Post in `#team-vault-eco-tfvp` Slack channel to request a review from the Vault Ecosystem team.

---

## Changelog

- Update [`CHANGELOG.md`](../../CHANGELOG.md) for every user-facing change.
- If a change modifies a Vault API endpoint → note any required Vault policy updates.
- For features targeting an unreleased Vault version: note in the changelog that the feature requires the upcoming Vault release.

---

## Documentation

- Provider docs live in `website/`.
- Net-new resources/data sources require an entry in `website/vault.erb`.
- Note the minimum Vault version in docs for version-dependent parameters:
  ```
  * `some_parameter` - (Optional) Does something. Requires Vault 2.1+.
  * `some_ent_param` - (Optional) Enterprise only. Requires Vault Enterprise 2.1+.
  ```

---

## How to Work with AI on This Project

- **Minimal, targeted changes only.** Do not refactor unrelated code, add unsolicited abstractions, or clean up surrounding code.
- **Read before writing.** Always inspect the relevant existing resource file(s) before generating new code.
- **Follow existing patterns.** Match the style of the resource being modified — SDK vs framework, const usage, test structure.
- **Flag version dependencies.** If a Vault API feature is version-specific, say so and add an `IsAPISupported` guard.
- **Always include tests.** Any code change that adds or modifies a resource must include or update unit tests; flag when acceptance tests are also needed.
- **Check the PR checklist.** Before declaring work done, verify the items in the PR checklist above are addressed.
- **Propose CHANGELOG entries.** Suggest a CHANGELOG line for any user-facing change.
- **Ask before assuming.** If it's unclear whether a field should be `Computed`, `Optional`, or version-gated, ask rather than guess.
