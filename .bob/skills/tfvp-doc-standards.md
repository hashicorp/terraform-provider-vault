---
name: tfvp-doc-standards
description: >
  TFVP documentation standards: resource doc file structure, field documentation rules,
  example quality standards, sidebar registration, and changelog format.
  Activate when creating or reviewing provider documentation.
---

# TFVP Documentation Standards

## File Location
```
website/docs/r/{resource_name}.html.md    # resources
website/docs/d/{resource_name}.html.md    # data sources
```

## Document Template
```markdown
---
layout: "vault"
page_title: "Vault: vault_{resource} resource"
sidebar_current: "docs-vault-resource-{category}-{resource}"
description: |-
  One-line description of what this resource manages.
---

# vault\_{resource}

Detailed description: what the resource does, when to use it,
any prerequisites, Vault version requirements, or Enterprise-only notes.

~> **Important** Use this callout for security warnings or critical notices.

## Example Usage

### Basic Example
```hcl
# Minimal working configuration — required fields only
resource "vault_{resource}" "example" {
  mount = vault_mount.example.path
  name  = "example"
}
```

### Advanced Example
```hcl
# Full configuration demonstrating all features
resource "vault_{resource}" "advanced" {
  mount    = vault_mount.example.path
  name     = "advanced"
  optional = "value"
}
```

## Argument Reference

* `namespace` - (Optional) Namespace to provision the resource in.
  Value must not have leading or trailing slashes.
  Always relative to the provider's configured namespace.
  *Available only for Vault Enterprise.*

* `field_name` - (Required/Optional) Description of the field.
  Valid values: ..., Default: ...

## Attributes Reference

* `id` - The ID of the resource.
* `computed_field` - Description of what this computed field contains.

## Import

{Resource} can be imported using the `{mount}/{name}` format:

```
$ terraform import vault_{resource}.example mount-path/resource-name
```

## Notes

* Any important behavioural notes or common pitfalls.
```
## Field Documentation Rules
| Field type | Marker | Notes |
|---|---|---|
| Required | `(Required)` | Explain why it's mandatory |
| Optional | `(Optional)` | State the default value |
| Computed | `(Computed)` | Explain when/how it's set |
| Sensitive | `(Sensitive)` | Note it won't appear in logs |
| Write-only | explicit note | "This field is write-only and will not be read back from Vault" |
| Format | example | Show format e.g. `host:port`, `YYYY-MM-DD` |

## Example Quality Standards
- **Runnable**: copy-paste ready with all dependencies included
- **Realistic**: use realistic values, not `"xxx"` or `"TODO"`
- **Progressive**: basic example first, advanced example second
- **Variable usage**: show `var.password` for sensitive fields
- **Commented**: explain non-obvious configuration choices
```

## Changelog Format
File: `.changelog/{PR_NUMBER}.txt`
```
```release-note:feature
secrets/{engine}: Add `vault_{resource}` resource for {description}
```
```

Categories: `feature` · `improvement` · `bug` · `note` (breaking changes)

## Documentation Completeness Checklist
- [ ] Description is clear and explains purpose
- [ ] Basic example is minimal and runnable
- [ ] Advanced example demonstrates all optional fields
- [ ] Every argument documented with type, requirement, and purpose
- [ ] All computed attributes listed in Attributes Reference
- [ ] Sensitive / write-only fields explicitly noted
- [ ] Import format documented with real example command
- [ ] Vault version or Enterprise requirements stated
- [ ] Security warnings in `~>` callout blocks
- [ ] Sidebar entry added to `website/vault.erb`
- [ ] Changelog entry created in `.changelog/`
