---
name: tfvp-test-patterns
description: >
  TFVP acceptance test patterns: test structure, naming conventions, import test helpers,
  write-only field handling, and regression testing requirements.
  Activate when writing or reviewing test files.
---

# TFVP Test Patterns

## Test Philosophy (Vladimir Khorikov)
- Test **observable behaviour**, not implementation details
- Test **state matches expectations** — not internal methods
- Each test runs **independently** with no side effects
- **Arrange → Act → Assert** structure in every step
- Don't assert on Vault error message text (it changes between versions)

## Standard Test Structure
```go
func TestAccMyResource_basic(t *testing.T) {
    resource.Test(t, resource.TestCase{
        ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
        PreCheck: func() {
            acctestutil.TestAccPreCheck(t)
            acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200) // if version-gated
        },
        Steps: []resource.TestStep{
            {   // Step 1: Create
                Config: testConfigMyResource_basic("initial"),
                Check: resource.ComposeTestCheckFunc(
                    resource.TestCheckResourceAttr("vault_my_resource.test", "name", "initial"),
                    resource.TestCheckResourceAttrSet("vault_my_resource.test", "computed_field"),
                ),
            },
            // Step 2: Import
            testutil.GetImportTestStep("vault_my_resource.test", false, nil, "password"),
            {   // Step 3: Update
                Config: testConfigMyResource_basic("updated"),
                Check: resource.ComposeTestCheckFunc(
                    resource.TestCheckResourceAttr("vault_my_resource.test", "name", "updated"),
                ),
            },
        },
    })
}
```

## Test Naming Conventions
| Test name | Purpose |
|---|---|
| `TestAccResource_basic` | Happy path CRUD + import |
| `TestAccResource_remount` | Backend path change |
| `TestAccResource_optionalFields` | Add / remove optional fields |
| `TestAccResource_writeOnly` | Write-only field preserved across plan cycles |
| `TestAccResource_computed` | Computed fields set by Vault API |
| `TestAccResource_regression_<scenario>` | Regression for specific scenario |

## Import Test Patterns
```go
// Simple: ignore write-only fields
testutil.GetImportTestStep("vault_my_resource.test", false, nil, consts.FieldPassword)

// Custom import ID (multi-part path)
func testAccMyResourceImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
    return func(s *terraform.State) (string, error) {
        rs, ok := s.RootModule().Resources[resourceName]
        if !ok {
            return "", fmt.Errorf("not found: %s", resourceName)
        }
        return fmt.Sprintf("%s/%s",
            rs.Primary.Attributes[consts.FieldMount],
            rs.Primary.Attributes[consts.FieldName]), nil
    }
}
```

## Test Coverage Requirements
| Scenario | Required |
|---|---|
| Create + Read | ✅ |
| Update | ✅ |
| Import (`ImportState: true`, `ImportStateVerify: true`) | ✅ |
| Computed fields set after create | ✅ |
| Optional fields added then removed | ✅ |
| Write-only fields preserved in state | ✅ if field exists |
| Remount (backend path change) | ✅ if applicable |
| `testutil.SkipTestEnvSet` for unreleased Vault features | ✅ if feature-gated |

## Regression Test Requirements
When modifying an existing resource, add regression tests that verify:
- Old configurations still apply without error
- Existing field behaviour is unchanged
- Default values remain consistent
- Computed fields still compute correctly
- Previously valid values still pass validation

## What NOT to Test
- ❌ Vault API error message text (changes between versions)
- ❌ Provider internal state management details
- ❌ Internal implementation methods
- ❌ Negative test cases driven by exact error string comparison
- ❌ Vault behaviour that may change in future versions

## Config Helper Conventions
```go
// Use descriptive names, one function per scenario
func testConfigMyResource_basic(name string) string {
    return fmt.Sprintf(`
resource "vault_database_backend" "test" {
  path = "db-%s"
}
resource "vault_my_resource" "test" {
  mount = vault_database_backend.test.path
  name  = %q
}`, name, name)
}

func testConfigMyResource_withOptional(name, extra string) string { ... }
```

## SDK v2 vs Plugin Framework Test Differences
| Concern | SDK v2 | Plugin Framework |
|---|---|---|
| Provider factories | `ProviderFactories` | `ProtoV6ProviderFactories` |
| Import testing | Identical | Identical |
| Attribute checks | `resource.TestCheckResourceAttr` | Same |
| Both can co-exist | ✅ | ✅ |
