# VAULT-41988 — Allow Custom Name for Registering Enterprise Plugins with TFVP

> **Triage recommendation:** This is a **Vault server-side gap**, not a TFVP issue.
> See [Conclusion](#conclusion--triage-recommendation) at the bottom.

**Jira:** [VAULT-41988](https://hashicorp.atlassian.net/browse/VAULT-41988)  
**Type:** Sub-task of [VAULT-41985](https://hashicorp.atlassian.net/browse/VAULT-41985) (State Street - Terraform Vault Provider)  
**Status:** Pending Triage  
**Reporter:** SUJANA SUBEDI  
**Label:** `state_street`

---

## Summary

The customer (State Street) wants to register a Vault Enterprise plugin under a **custom (alias) name** in the plugin catalog via TFVP, so existing Vault mounts that already reference that custom name continue to work.

---

## API Behaviour — Confirmed by Live Testing

Three curl tests were run against a live Vault Enterprise cluster to understand how the API behaves.

### Test 1 — Body `name` ≠ URL path name (original hypothesis)
```
PUT /v1/sys/plugins/catalog/database/custom-oracle
Body: { "name": "vault-plugin-database-oracle", "version": "v0.14.1+ent" }
```
**Result:** Vault looked for `/opt/vault/plugin/custom-oracle_0.14.1+ent_linux_amd64/custom-oracle` on disk — i.e. the folder and binary must be named after the **URL path name**, not the body `name`. The body `name` field has no influence on disk path resolution.

### Test 2 — Body `name` reversed
```
PUT /v1/sys/plugins/catalog/database/vault-plugin-database-oracle
Body: { "name": "custom-oracle", "version": "v0.14.1+ent" }
```
Read back:
```json
{
  "data": {
    "name": "vault-plugin-database-oracle",
    "command": "vault-plugin-database-oracle_0.14.1+ent_linux_amd64/vault-plugin-database-oracle",
    "version": "v0.14.1+ent"
  }
}
```
**Result:** Vault **completely ignored** the body `name` field (`"custom-oracle"`). The catalog entry `data.name` was set to the URL path name (`vault-plugin-database-oracle`). The body `name` field is a no-op — Vault always overwrites it with the URL path name.

### Conclusion from testing

| Field | Actual role |
|---|---|
| URL path `:name` | Controls the catalog key, the expected folder name on disk, and the binary name inside the folder |
| Body `name` | **Ignored by Vault** — always overwritten with the URL path name |

---

## Revised Understanding of the Feature Request

There is **no API body field to implement** in the provider. The Vault API already supports custom plugin names — you simply set `name` in the `vault_plugin` resource to whatever custom name you want. The catch is entirely on the **Vault server disk**:

When registering `name = "custom-oracle"` with version `v0.14.1+ent` on `linux/amd64`, the operator must prepare the Vault server with:

```
<plugin_directory>/
└── custom-oracle_0.14.1+ent_linux_amd64/
    └── custom-oracle                    ← binary must also be named custom-oracle
```

The `vault_plugin` resource in TFVP already passes `name` as the URL path name. **No Go code changes are needed.**

---

## Required Changes — Documentation Only

### `website/docs/r/plugin.html.md`

Add a new example section and a `> Note` callout explaining the disk requirement:

````markdown
### Register an Enterprise plugin under a custom catalog name

When registering an enterprise plugin under a name that differs from the
canonical HashiCorp release name, the Vault server's plugin directory must
contain a folder and binary named after the **custom name** (not the
canonical release name).

> **Note:** Vault resolves the plugin binary from disk using the catalog
> `name` (the value set in the `name` argument). For a custom name, you must
> prepare the plugin directory on every Vault server node before applying
> this resource.

**On each Vault server node:**
```bash
PLUGIN_DIR="/opt/vault/plugin"         # your configured plugin_directory
CUSTOM_NAME="custom-oracle"
VERSION="0.14.1+ent"
ARCH="linux_amd64"
CANONICAL="vault-plugin-database-oracle"

# 1. Download the zip from releases.hashicorp.com
curl -Lo /tmp/${CANONICAL}_${VERSION}_${ARCH}.zip \
  "https://releases.hashicorp.com/${CANONICAL}/${VERSION}/${CANONICAL}_${VERSION}_${ARCH}.zip"

# 2. Extract directly into a folder named after the CUSTOM name
#    (the zip contains: EULA.txt, metadata.json, metadata.json.sig,
#     TermsOfEvaluation.txt, and the binary — all go into this folder)
mkdir -p "${PLUGIN_DIR}/${CUSTOM_NAME}_${VERSION}_${ARCH}"
unzip -o /tmp/${CANONICAL}_${VERSION}_${ARCH}.zip \
  -d "${PLUGIN_DIR}/${CUSTOM_NAME}_${VERSION}_${ARCH}/"

# 3. Rename only the binary to match the custom catalog name
#    (leave EULA.txt, metadata.json, etc. as-is)
mv "${PLUGIN_DIR}/${CUSTOM_NAME}_${VERSION}_${ARCH}/${CANONICAL}" \
   "${PLUGIN_DIR}/${CUSTOM_NAME}_${VERSION}_${ARCH}/${CUSTOM_NAME}"

chmod 755 "${PLUGIN_DIR}/${CUSTOM_NAME}_${VERSION}_${ARCH}/${CUSTOM_NAME}"
```

The folder must look like this:
```
<plugin_directory>/
└── custom-oracle_0.14.1+ent_linux_amd64/
    ├── EULA.txt
    ├── metadata.json
    ├── metadata.json.sig
    ├── TermsOfEvaluation.txt
    └── custom-oracle                ← binary renamed to match catalog name
```

**Terraform resource:**
```hcl
resource "vault_plugin" "oracle_custom" {
  type    = "database"
  name    = "custom-oracle"    # matches the folder/binary name prepared above
  version = "v0.14.1+ent"
}
```
````

---

## Files to Change

| File | Change Type | Notes |
|---|---|---|
| [`website/docs/r/plugin.html.md`](website/docs/r/plugin.html.md) | Modify | Add custom-name example and disk-prep note |
| [`CHANGELOG.md`](CHANGELOG.md) | Modify | Add entry to unreleased section |
| [`vault/resource_plugin.go`](vault/resource_plugin.go) | **No change** | `name` already passed as URL path; no body field needed |
| [`internal/consts/consts.go`](internal/consts/consts.go) | **No change** | No new constants needed |

---

## CHANGELOG entry

```markdown
* `vault_plugin`: Add documentation example for registering an Enterprise plugin
  under a custom catalog name, including required Vault server disk preparation.
  ([#XXXX](https://github.com/hashicorp/terraform-provider-vault/pull/XXXX))
```

---

## Development Workflow Checklist

- [ ] Branch: `plugin-custom-name`
- [ ] Update [`website/docs/r/plugin.html.md`](website/docs/r/plugin.html.md) — add custom-name example + disk-prep note
- [ ] Update [`CHANGELOG.md`](CHANGELOG.md)
- [ ] Open PR and milestone to next release
