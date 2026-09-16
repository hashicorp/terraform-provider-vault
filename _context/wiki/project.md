# Project Overview

## What this project is

The **Terraform Vault Provider (TFVP)** (`github.com/hashicorp/terraform-provider-vault`) is a Terraform provider maintained by the **Vault Ecosystem team at HashiCorp**. It allows DevOps/platform engineers to manage HashiCorp Vault resources — secrets engines, auth methods, policies, namespaces, identity entities, and more — as infrastructure-as-code using Terraform.

The provider began as a community-driven project and is now owned by the Vault Ecosystem team. It does not yet have full feature parity with Vault; closing that gap and keeping pace with new Vault API changes is the primary ongoing mission.

**Key rule:** If a Vault feature is configurable via the Vault API, it should have TFVP support. Exceptions: seal/unseal and anything related to bootstrapping Vault (TFVP assumes a running, unsealed server).

---

## Main Goals and Objectives

1. **Feature parity** — Close the backlog of Vault API features not yet represented in TFVP resources/data sources.
2. **Stay current** — Every new Vault feature that touches the API should have a corresponding TFVP update included in the Definition of Done.
3. **Bug & regression hygiene** — Field and triage bugs for owned resources promptly; include TFVP in sustaining engineering rotations.
4. **Scale development** — Onboard Vault domain-team developers to contribute TFVP changes for their subsystems.

---

## Key Stakeholders / Users

- **Primary users:** DevOps and platform engineers managing Vault via Terraform.
- **Vault Ecosystem team:** Owns and maintains the provider; performs releases; reviews PRs.
- **Vault domain teams:** Expected to contribute TFVP updates for their own Vault subsystems.
- **Support channel:** `#team-vault-eco-tfvp` on Slack.
- **Releases:** Mid-month, roughly once per month, independent of Vault's release cycle.

---

## Repository Structure

| Path | Purpose |
|------|---------|
| `vault/` | All Terraform resources (`resource_*.go`) and data sources (`data_source_*.go`). Each resource has a paired `_test.go` file. |
| `internal/consts/` | Shared field-name constants — always use these instead of raw strings. |
| `internal/framework/` | Framework helpers: base resource types, client wrappers, error utils, validators, token helpers, rotation logic. |
| `internal/provider/` | Provider registration and configuration. |
| `internal/providertest/` | Test helpers shared across acceptance tests. |
| `internal/vault/` | Internal Vault API interaction utilities. |
| `internal/pki/`, `internal/sync/`, `internal/rotation/`, `internal/identity/` | Domain-specific helpers for PKI, Secrets Sync, credential rotation, and Identity. |
| `website/` | HCL-docs-based provider documentation. |
| `scripts/` | CI helper scripts (Go version check, fmt check, etc.). |
| `codegen/` | Code generation tooling. |
| `testutil/`, `acctestutil/` | Shared test utilities. |
| `helper/` | Miscellaneous shared helpers. |

---

## Key Workflows

### Development workflow
1. Pick or create a Jira ticket (`VAULT-XXXX`).
2. Create a branch named `VAULT-XXXX/short-description`.
3. Implement resource/data source change in `vault/`.
4. Use constants from `internal/consts/` for all field names.
5. Write/update unit tests (`make test`) and acceptance tests (`make testacc`).
6. Update `CHANGELOG.md` and `website/` docs.
7. Open PR, ensure CI is green, request review from Vault Ecosystem via `#team-vault-eco-tfvp`.
8. Milestone the PR to the target release (e.g. `3.13.0`).

### Feature branching
For multi-PR features: create a feature branch named `VAULT-XXXX/subsystem/feature-name`; merge individual PRs into it; open a single final PR into `main` or `release/vault-next`.

### Version gating
Features only available in specific Vault versions must be gated with `provider.IsAPISupported` in both the resource and test files.

### Acceptance testing
Requires a running, unsealed Vault instance. Set `VAULT_ADDR` and `VAULT_TOKEN`. Run:
```sh
make testacc TESTARGS='-run=TestAccXXX'
```
For enterprise-only tests: `make testacc-ent`.

---

## Pain Points / Complexity Hotspots

- **Schema/API drift:** Vault API fields change between versions; TFVP schemas must be kept in sync. Requires careful version-gating via `provider.IsAPISupported`.
- **Acceptance tests need live Vault:** Unit tests can run anywhere; acceptance tests require a real Vault instance with the right env vars set.
- **SDK dual-stack:** The provider uses both `terraform-plugin-sdk/v2` (legacy SDK, most resources in `vault/`) and `terraform-plugin-framework` (newer framework, resources in `internal/framework/`). New resources should prefer the framework where possible.
- **Duration fields:** Always use integer (seconds) schema types for duration fields — never strings — due to Vault API inconsistency in how durations are returned on read (e.g. `1h` in, `3600` out).
- **Computed vs Default:** If Vault returns a default for a field, mark it `Computed` (not `Default`). Exception: boolean fields with a default of `true` should use `Default`.
- **Deprecated `GetOkExists`:** Do not use `d.GetOkExists()` in new code; use `d.Get()` or `d.GetOk()`.
- **`d.Get` in Read functions:** Generally discouraged (breaks `terraform import`). Use it only for sensitive fields that Vault redacts on read.

---

## Important Links

- [TFVP Developer Guide (Confluence)](https://hashicorp.atlassian.net/wiki/spaces/VAULT/pages/2331443254)
- [TFVP Developer Onboarding (Confluence)](https://hashicorp.atlassian.net/wiki/spaces/VAULT/pages/2661023745/TFVP+Developer+Onboarding)
- [TFVP Development Best Practices (Confluence)](https://hashicorp.atlassian.net/wiki/spaces/VAULT/pages/2661089281/TFVP+Development+Best+Practices)
- [TFVP Pull Request Checklist (Confluence)](https://hashicorp.atlassian.net/wiki/spaces/VAULT/pages/2960851087/TFVP+Pull+Request+Checklist)
- [TFVP Development Basics (Confluence)](https://hashicorp.atlassian.net/wiki/spaces/VAULT/pages/2661056573/TFVP+Development+Basics)
- [TFVP Feature Parity Tracker (Google Sheets)](https://docs.google.com/spreadsheets/d/1voJBsxK4qKGz7YmhjjUqzh-s-cUdEPcuIcZFXJM0uLI/edit#gid=0)
- [GitHub open issues](https://github.com/hashicorp/terraform-provider-vault/issues)
- [Vault API docs](https://developer.hashicorp.com/vault/api-docs)
