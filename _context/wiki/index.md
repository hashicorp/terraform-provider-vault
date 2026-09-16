# Wiki Index

This wiki captures durable context about the `terraform-provider-vault` project and how work is done here.
Read this index first; follow links only when they are relevant to your task.

## Files

| File | What it covers |
|------|---------------|
| [project.md](project.md) | What the project is, goals, key modules, workflows, pain points |
| [preferences.md](preferences.md) | Code style, PR standards, AI working preferences |

## Quick-reference

- **Primary working directories:** `vault/` (resources & data sources), `internal/` (helpers, framework, consts)
- **Run unit tests:** `make test`
- **Run acceptance tests (needs live Vault):** `make testacc TESTARGS='-run=TestAccXXX'`
- **Local dev build:** `make dev`
- **Key rule:** If a Vault feature is configurable via the Vault API, it needs TFVP support.
- **Slack support channel:** `#team-vault-eco-tfvp`
