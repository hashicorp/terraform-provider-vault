---
name: tfvp-code-patterns
description: >
  TFVP implementation patterns: resource structure, client usage, sensitive fields,
  read-after-write, import, schema modifiers, and provider registration.
  Activate when implementing or reviewing new resources/data sources.
---

# TFVP Code Patterns

## Resource File Structure
```
internal/vault/secrets/{engine}/
├── {resource}_resource.go
├── {resource}_resource_test.go
└── helpers.go          # ID builders, parsers, shared logic
```

## Resource Skeleton
```go
type MyResource struct {
    base.ResourceWithConfigure
}

type MyResourceModel struct {
    base.BaseModelLegacy
    // Fields with `tfsdk:"field_name"` tags
}

// Required interface methods (resource.Resource)
func (r *MyResource) Metadata(...)
func (r *MyResource) Schema(...)
func (r *MyResource) Create(...)
func (r *MyResource) Read(...)
func (r *MyResource) Update(...)
func (r *MyResource) Delete(...)

// Optional import support (resource.ResourceWithImportState)
// ImportState is a SEPARATE optional interface — not part of resource.Resource.
// Only implement it if the resource supports `terraform import`.
func (r *MyResource) ImportState(...)

// Compile-time interface checks (recommended)
var _ resource.Resource = &MyResource{}
var _ resource.ResourceWithImportState = &MyResource{}
```

## Client Acquisition (Correct Pattern)
```go
// CORRECT
cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
if err != nil {
    resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
    return
}

// WRONG — do not use r.GetClient()
```

## Read After Write (Critical)
Every Create and Update MUST call Read before setting state:
```go
func (r *MyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
    // ... write to Vault ...
    r.readFromVault(ctx, cli, &data, &resp.Diagnostics)
    if resp.Diagnostics.HasError() {
        return
    }
    resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
```

## 404 Handling
```go
if secret == nil {
    resp.State.RemoveResource(ctx)   // Plugin Framework
    // or for SDK v2:
    // d.SetId("")
    return
}
```

## Sensitive Fields vs Write-Only Fields

These are **two distinct concepts** in Plugin Framework — do not conflate them:

| | `Sensitive: true` | `WriteOnly: true` |
|---|---|---|
| Value stored in state? | ✅ Yes (masked in output) | ❌ Never — always `null` in state |
| Accepts ephemeral values? | ❌ No | ✅ Yes (Terraform 1.11+) |
| Can produce plan diff? | ✅ Yes | ❌ No (always null→null) |
| Use case | Passwords stored in state, masked in logs | Secrets that must NOT be persisted at all |

```go
// SENSITIVE: stored in state but redacted in Terraform output
consts.FieldPassword: schema.StringAttribute{
    Required:  true,
    Sensitive: true,
    MarkdownDescription: "Password. Stored in state but masked in output.",
},
// Read: keep plan value in state — never overwrite from API response
data.Password = state.Password

// WRITE-ONLY (Framework ≥1.11, Terraform ≥1.11): never persisted at all
consts.FieldPassword: schema.StringAttribute{
    Required:  true,
    WriteOnly: true,
    MarkdownDescription: "Password (write-only). Not stored in Terraform state.",
},
// No need to null it out — the framework handles nullification automatically.
// Value is only available in req.Config during Create/Update, not in state.
```

## Import Implementation
```go
func (r *MyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
    mount, name, err := parseResourceID(req.ID)
    if err != nil {
        resp.Diagnostics.AddError("Invalid import ID", err.Error())
        return
    }

    var data MyResourceModel
    data.ID    = types.StringValue(makeResourceID(mount, name))
    data.Mount = types.StringValue(mount)
    data.Name  = types.StringValue(name)

    cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
    if err != nil {
        resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
        return
    }

    r.readFromVault(ctx, cli, &data, &resp.Diagnostics)
    if resp.Diagnostics.HasError() {
        return
    }
    resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
```

## Common Schema Modifiers
```go
// Immutable field — forces replacement on change
consts.FieldMount: schema.StringAttribute{
    Required: true,
    PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
},

// Computed field — preserve across plan/apply cycles
"last_rotation": schema.StringAttribute{
    Computed: true,
    PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
},

// Optional with a static default
consts.FieldPort: schema.Int64Attribute{
    Optional: true,
    Computed: true,
    Default:  int64default.StaticInt64(22),
},

// Map attribute
"custom_metadata": schema.MapAttribute{
    ElementType: types.StringType,
    Optional:    true,
},
```

## Field Naming Rules
| Resource Type | Field | Constant |
|---|---|---|
| Backend-mounting (configures a mount) | `path` | `consts.FieldPath` |
| Non-backend-mounting (uses existing mount) | `mount` | `consts.FieldMount` |
| **Never use** `backend` field | — | deprecated |

## Constants
All new field name strings go in `internal/consts/consts.go`:
```go
const (
    FieldMyNewField = "my_new_field"
)
```

## Provider Registration
Add to `internal/provider/fwprovider/provider.go` → `Resources()` method:
```go
func (p *fwprovider) Resources(_ context.Context) []func() resource.Resource {
    return []func() resource.Resource{
        // ... existing entries ...
        myengine.NewMyResource,
    }
}
```

## Framework vs SDK v2 Key Differences
| Concern | SDK v2 | Plugin Framework |
|---|---|---|
| Schema | `map[string]*schema.Schema` | Typed attributes (`schema.StringAttribute` etc.) |
| State read | `d.Get()` / `d.GetOk()` | `req.Plan.Get(ctx, &data)` or `req.State.Get(ctx, &data)` |
| State write | `d.Set("field", val)` | `resp.State.Set(ctx, &data)` |
| Errors | `return diag.FromErr(err)` | `resp.Diagnostics.AddError(...)` |
| Import | `schema.ResourceImporter{StateContext: ...}` | Separate `resource.ResourceWithImportState` interface |
| Import (simple) | `schema.ImportStatePassthroughContext` | `resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)` |
| 404 | `d.SetId("")` | `resp.State.RemoveResource(ctx)` |
| Null handling | Zero values | Explicit `types.StringNull()`, `types.StringUnknown()` etc. |
| Validators | `ValidateFunc` | `stringvalidator.*`, `int64validator.*` |
| Write-only secrets | Manual: keep in state from plan | Native: `WriteOnly: true` (Terraform 1.11+, never stored) |
| Configure | `meta interface{}` in CRUD funcs | `resource.ResourceWithConfigure` interface + `Configure` method |

## Migration Gotchas: SDK v2 → Plugin Framework

> Activate this section when migrating an existing SDK v2 resource. All points below are
> behaviours that differ from SDK v2 in ways that are easy to miss and will cause runtime errors.

### 1. All four CRUD methods are required — even if empty

SDK v2 lets you omit `Update` when a resource requires replacement. The Framework's
`resource.Resource` interface is strict — **all four methods must be implemented**.  
An empty `Update` that does nothing is valid; omitting it fails to compile.

```go
// Framework: Update must exist even for immutable resources
func (r *MyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
    // All fields use RequiresReplace, so this should never be called.
    // Implement anyway to satisfy the interface.
}
```

### 2. `Update` must explicitly copy plan → state (SDK v2 did it automatically)

In SDK v2, an empty or missing `Update` silently copies the plan to state.  
In the Framework, if `Update` does not call `resp.State.Set(ctx, &data)`, Terraform returns:
> `Provider produced inconsistent result after apply`

```go
func (r *MyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
    var data MyResourceModel
    resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
    // ... API call ...
    resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)  // required — never omit
}
```

### 3. `Delete` auto-removes resource from state — do NOT call `RemoveResource` explicitly

SDK v2: you signal deletion with `d.SetId("")`.  
Framework: `Delete` automatically calls `resp.State.RemoveResource(ctx)` when it returns
without errors. **Calling it explicitly inside `Delete` causes a double-remove error.**  
Only call `resp.State.RemoveResource(ctx)` explicitly inside `Read` (for 404 handling).

### 4. Schema type mapping (SDK v2 → Framework)

| SDK v2 type | Framework attribute |
|---|---|
| `schema.TypeString` | `schema.StringAttribute` / `types.String` |
| `schema.TypeInt` | `schema.Int64Attribute` / `types.Int64` |
| `schema.TypeFloat` | `schema.Float64Attribute` / `types.Float64` |
| `schema.TypeBool` | `schema.BoolAttribute` / `types.Bool` |
| `schema.TypeList` (primitive) | `schema.ListAttribute{ElementType: types.StringType}` |
| `schema.TypeList` (block) | `schema.ListNestedAttribute` |
| `schema.TypeSet` (primitive) | `schema.SetAttribute{ElementType: types.StringType}` |
| `schema.TypeSet` (block) | `schema.SetNestedAttribute` |
| `schema.TypeMap` | `schema.MapAttribute{ElementType: types.StringType}` |

Model struct fields use `tfsdk:"field_name"` tags (not `json:` or `mapstructure:`).

### 5. Data consistency errors surface as hard errors (not silent warnings)

SDK v2 tolerates value mismatches (e.g. API normalising `"value"` → `"VALUE"`) with only
a warning log. The Framework surfaces these as hard practitioner errors.

**Fix**: when the API normalises values (e.g. uppercasing, trimming), use a custom type
with semantic equality logic, or normalise the value in `Create`/`Update` before setting state.

### 6. `StateFunc` has no direct equivalent — use a plan modifier or custom type

SDK v2's `StateFunc` (transform a value before storing it in state) maps to:
- A **plan modifier** (`PlanModifyString`) for deterministic transformations, or
- A **custom type** with `StringSemanticEquals` for case-insensitive / normalisation scenarios.

### 7. Import: `Importer` field → `resource.ResourceWithImportState` interface

| SDK v2 | Framework |
|---|---|
| `Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext}` | `resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)` |
| Custom `StateContextFunc` that calls `d.Set(...)` | Custom `ImportState` that calls `resp.State.SetAttribute(ctx, path.Root(...), value)` |

During import, **neither SDK v2 nor Framework** has access to config, state, or plan —
only the ID string from `terraform import` / `import` block is available.

### 8. `StateUpgraders` → `UpgradeState` method

If the SDK v2 resource sets `SchemaVersion > 0` and has `StateUpgraders`, migrate each
upgrader to the Framework's `resource.ResourceWithUpgradeState` interface:

```go
var _ resource.ResourceWithUpgradeState = &MyResource{}

func (r *MyResource) UpgradeState(ctx context.Context) map[int64]resource.StateUpgrader {
    return map[int64]resource.StateUpgrader{
        0: { /* upgrade from version 0 to current */ },
    }
}
```

### 9. `CustomizeDiff` → plan modifiers and/or `resource.ResourceWithModifyPlan`

SDK v2's `CustomizeDiff` maps to:
- **Attribute-level plan modifiers** (`PlanModifiers` field on the attribute) for common cases
- The `resource.ResourceWithModifyPlan` interface (`ModifyPlan` method) for cross-attribute logic

### 10. Coexistence: SDK v2 and Framework resources in the same provider (muxing)

During incremental migration, both frameworks can coexist via `terraform-plugin-mux`.
TFVP uses this today — Framework resources live in `internal/provider/fwprovider/`,
SDK v2 resources remain in `vault/`. A resource must be fully in one framework — never split.
