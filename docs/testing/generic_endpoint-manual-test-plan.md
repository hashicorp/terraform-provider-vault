# Manual Test Plan & Results — `vault_generic_endpoint` action

Covers PR [#2956](https://github.com/hashicorp/terraform-provider-vault/pull/2956) (issue
[#2954](https://github.com/hashicorp/terraform-provider-vault/issues/2954)).

Executed 2026-09-04 against the `vault_generic_endpoint` action. An earlier revision of this
document covered `vault_secret_backend_rotate_root`, which took `backend` + `name` and built the
path itself. That action was replaced by this one, which takes the full `path`, so every case
below was **re-executed** — none of the results are carried over.

## 1. Scope

The action performs one Vault API call:

```
PUT /v1/{path}
```

with an optional JSON request body. The path is supplied verbatim by the user, so the provider
does no engine-specific path construction at all. The engine-by-engine differences that made the
previous design awkward — `{mount}/rotate-root/{name}` for databases, `{mount}/config/rotate-root`
for AWS and GCP, `{mount}/rotate-root` for the rest — are now expressed entirely in configuration.

That shapes this plan. What is worth testing is:

1. **Real rotation, end to end, on three engines with different path shapes** — Database, LDAP and
   AWS. Each confirmed by an out-of-band check that the *old* credential no longer authenticates.
2. **A non-rotation endpoint with a request body**, to confirm the action is genuinely generic
   rather than a rotate-root helper wearing a different name.
3. **Negative and validation paths**, which is where the remaining provider logic lives.

Azure, GCP and AD are not run live; they issue the identical single write to a path the user
supplies. See §7.

## 2. Environment

| Component | Version / detail |
|---|---|
| Provider | branch `action-rotate-root`, working tree (unpushed) |
| Terraform | 1.15.2 (actions require ≥ 1.14.0) |
| Vault | 2.0.3 Community Edition, `-dev` mode, `http://127.0.0.1:8200` |
| Go | 1.26.6 darwin/arm64 |
| PostgreSQL | 18.3 (Homebrew), `127.0.0.1:5433` |
| OpenLDAP | 2.6.10 (`bitnamilegacy/openldap`), `127.0.0.1:1389` |
| AWS | account `717316313319`, throwaway IAM user created and deleted for the test |
| Executed | 2026-09-04 |

Provider loaded via `dev_overrides`; a Vault file audit device at `rr/` captured every call.

## 3. Setup

```bash
# Vault
vault server -dev -dev-root-token-id=root -dev-listen-address=127.0.0.1:8200 &
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
vault audit enable -path=rr file file_path=/tmp/audit.log

# Provider
go build -o "$BIN/terraform-provider-vault" .
cat > "$TFRC" <<EOF
provider_installation {
  dev_overrides { "hashicorp/vault" = "$BIN" }
  direct {}
}
EOF
export TF_CLI_CONFIG_FILE=$TFRC
```

> **Note:** Terraform has no `terraform invoke` command. Actions only fire through
> `lifecycle { action_trigger { ... } }` on a resource. Every case below hangs the action off
> either the resource under test or a bare `terraform_data` trigger.

### 3.1 PostgreSQL

```bash
pg_ctl -D "$PGDATA" initdb -o "-U postgres --auth=trust"
LC_ALL=C pg_ctl -D "$PGDATA" -o "-p 5433 -k /tmp" start
psql -h /tmp -p 5433 -U postgres \
  -c "CREATE ROLE rotate_root_user WITH LOGIN SUPERUSER PASSWORD 'rotate_root_password';"
# set the host lines in pg_hba.conf to scram-sha-256 so rotation is observable, then reload
```

### 3.2 OpenLDAP

```bash
podman run -d --name rr-ldap -p 1389:1389 \
  -e LDAP_ADMIN_USERNAME=admin -e LDAP_ADMIN_PASSWORD=adminpassword \
  -e LDAP_ROOT=dc=example,dc=org docker.io/bitnamilegacy/openldap:latest
```

Create a **dedicated bind user** rather than using the directory root, matching the warning in the
action docs:

```bash
ldapadd -x -H ldap://127.0.0.1:1389 -D "cn=admin,dc=example,dc=org" -w adminpassword <<'EOF'
dn: cn=vaultbind,ou=users,dc=example,dc=org
objectClass: inetOrgPerson
cn: vaultbind
sn: vaultbind
uid: vaultbind
userPassword: vaultbindpassword
EOF
```

Bitnami's default ACL does not grant self-write on `userPassword`, so rotation fails with
`Insufficient Access Rights` until this is added:

```bash
podman exec rr-ldap ldapmodify -Y EXTERNAL -H ldapi:/// <<'EOF'
dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to * by self read by users read by * none
EOF
```

### 3.3 AWS

```bash
aws iam create-user --user-name vault-rotate-root-test
aws iam put-user-policy --user-name vault-rotate-root-test --policy-name self-rotate \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
    "Action":["iam:GetUser","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"],
    "Resource":"arn:aws:iam::<ACCOUNT>:user/vault-rotate-root-test"}]}'
aws iam create-access-key --user-name vault-rotate-root-test
```

> The IAM user must manage **its own** access keys, and an IAM user is limited to two. Rotation
> creates a new key and **deletes the old one outright** — never point this at a user whose key
> anything still depends on.

## 4. Positive cases

Each rotation is confirmed the same way: show the old credential authenticates, rotate, then show
it no longer does. A successful apply proves nothing on its own.

### P1 — Database (PostgreSQL) — `{mount}/rotate-root/{name}`

```hcl
resource "vault_database_secret_backend_connection" "postgres" {
  backend       = vault_mount.db.path
  name          = "postgres"
  allowed_roles = ["*"]

  postgresql {
    connection_url = "postgres://{{username}}:{{password}}@127.0.0.1:5433/postgres?sslmode=disable"
    username       = "rotate_root_user"
    password       = "rotate_root_password"
  }

  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.vault_generic_endpoint.rotate_postgres]
    }
  }
}

action "vault_generic_endpoint" "rotate_postgres" {
  config {
    path = "${vault_mount.db.path}/rotate-root/${vault_database_secret_backend_connection.postgres.name}"
  }
}
```

**Steps.** Confirm `psql` logs in with the known password → `terraform apply` → retry the login →
issue a dynamic credential to prove Vault holds the new password.

**Actual — PASS.**

```
Action ...: Writing to mt1-database/rotate-root/postgres
Action ...: Successfully wrote to mt1-database/rotate-root/postgres
Apply complete! Resources: 2 added, 0 changed, 0 destroyed. Actions: 1 invoked.

$ PGPASSWORD=rotate_root_password psql -h 127.0.0.1 -p 5433 -U rotate_root_user -d postgres
psql: error: ... FATAL:  password authentication failed for user "rotate_root_user"

$ vault read mt1-database/creds/r
dynamic cred user: v-token-r-VhLTmAp50Zn0fdPWfylk-1788534336
```

### P2 — `after_create` does not re-fire on subsequent applies

**Actual — PASS.** A second `terraform apply` with no config change reported `No changes.`, printed
no `Actions: 1 invoked` line, and produced no new audit entry. Re-rotating requires
`terraform apply -replace` or a separate trigger. See [F4](#f4).

### P3 — LDAP — `{mount}/rotate-root`

```hcl
action "vault_generic_endpoint" "rotate_ldap" {
  config {
    path = "mt-ldap/rotate-root"
  }
}
```

**Actual — PASS.**

```
$ ldapwhoami -x -D "cn=vaultbind,ou=users,dc=example,dc=org" -w vaultbindpassword
dn:cn=vaultbind,ou=users,dc=example,dc=org            # before

Action ...: Successfully wrote to mt-ldap/rotate-root
Apply complete! Resources: 1 added, 0 changed, 0 destroyed. Actions: 1 invoked.

$ ldapwhoami -x -D "cn=vaultbind,ou=users,dc=example,dc=org" -w vaultbindpassword
ldap_bind: Invalid credentials (49)                   # after

$ vault write -f mt-ldap/rotate-root
Success! Data written to: mt-ldap/rotate-root         # rotating again still works
```

The second rotation is the proof Vault stored a *working* new password — a stale stored password
would have failed the bind.

### P4 — AWS — `{mount}/config/rotate-root`

```hcl
action "vault_generic_endpoint" "rotate_aws" {
  config {
    path = "mt-aws/config/rotate-root"
  }
}
```

**Actual — PASS.**

```
Action ...: Successfully wrote to mt-aws/config/rotate-root
Apply complete! Resources: 1 added, 0 changed, 0 destroyed. Actions: 1 invoked.

keys before: AKIA2OA3CKDTZ5JP5YYN
keys after:  AKIA2OA3CKDTRYYYCU4T      # old key deleted, not deactivated

$ AWS_ACCESS_KEY_ID=AKIA2OA3CKDTZ5JP5YYN ... aws sts get-caller-identity
An error occurred (InvalidClientTokenId) ... The security token included in the request is invalid.

$ vault read mt-aws/config/root
access_key = AKIA2OA3CKDTRYYYCU4T
```

Temp IAM user and key deleted afterwards.

### P5 — Non-rotation endpoint with a request body

This is the case the previous design could not express at all. It confirms `data_json` reaches
Vault and that the action is genuinely generic.

```hcl
action "vault_generic_endpoint" "write_policy" {
  config {
    path      = "sys/policies/acl/tf-action-test"
    data_json = jsonencode({ policy = "path \"secret/*\" { capabilities = [\"read\"] }" })
  }
}
```

**Actual — PASS.**

```
Action ...: Successfully wrote to sys/policies/acl/tf-action-test
Apply complete! Resources: 1 added, 0 changed, 0 destroyed. Actions: 1 invoked.

$ vault policy read tf-action-test
path "secret/*" { capabilities = ["read"] }
```

## 5. Negative cases

All run through a bare `terraform_data` trigger. Note which fail at *plan* time — those are schema
validators rejecting the config before any request reaches Vault.

| # | Case | Config | When | Result | Observed |
|---|---|---|---|---|---|
| N1 | Mount does not exist | `path = "nonexistent-backend/rotate-root/nope"` | apply | **PASS** | `404 — no handler for route "nonexistent-backend/rotate-root/nope"` |
| N2 | Valid mount, unknown connection | `path = "mt1-database/rotate-root/no-such-connection"` | apply | **PASS** | `500 — failed to find entry for connection with name: "no-such-connection"` |
| N3 | Timeout below minimum | `timeout_seconds = 30` | plan | **PASS** | `must be between 60 and 7200, got: 30` |
| N4 | Timeout above maximum | `timeout_seconds = 8000` | plan | **PASS** | `must be between 60 and 7200, got: 8000` |
| N5 | Leading slash in path | `path = "/mt1-database/rotate-root/postgres"` | plan | **PASS** | `value ... contains leading/trailing "/"` |
| N6 | Trailing slash in path | `path = "mt1-database/rotate-root/postgres/"` | plan | **PASS** | `value ... contains leading/trailing "/"` |
| N7 | `path` omitted | *(data_json only)* | plan | **PASS** | `The argument "path" is required` |
| N8 | `data_json` is not JSON | `data_json = "not-json"` | plan | **PASS** | `value must be a JSON object — invalid character 'o'` |
| N9 | `data_json` is a JSON array | `data_json = "[1,2,3]"` | plan | **PASS** | `cannot unmarshal array into Go value of type map[string]interface {}` |
| N10 | Token cannot mint a child token | policy without `auth/token/create` | apply | **PARTIAL** | Reported as `Failed to get Vault client`. See [F1](#f1) |
| N11 | Token denied on the target path | grants token create, denies write | apply | **PASS** | `403 permission denied` on `PUT .../rotate-root/postgres` |
| N12 | `namespace` against Community Edition | `namespace = "team-a"` | apply | **FINDING** | Silently succeeded against root namespace. See [F2](#f2) |
| N13 | `namespace` with slashes | `namespace = "/team-a/"` | plan | **PASS** | `value /team-a/ contains leading/trailing "/"` |
| N14 | AWS path missing `/config` | `path = "mt-aws/rotate-root"` | apply | **PASS** | `404 unsupported path` |

N14 is the mistake most likely to reach a real user. Under the previous design the provider
inserted `/rotate-root` itself and the `/config` segment was an undocumented trap; now the whole
path is visible in the config, and the 404 names exactly what was attempted.

## 6. Automated coverage

```
$ TF_ACC=1 POSTGRES_ROTATE_ROOT_URL='postgres://{{username}}:{{password}}@127.0.0.1:5433/postgres?sslmode=disable' \
    go test ./internal/vault/generic/... -run 'TestAccGenericEndpoint_' -v

--- PASS: TestAccGenericEndpoint_rotateRoot (0.90s)
--- PASS: TestAccGenericEndpoint_invalidPath (0.42s)
--- PASS: TestAccGenericEndpoint_leadingSlash (0.21s)
--- PASS: TestAccGenericEndpoint_invalidDataJSON (0.22s)
ok  github.com/hashicorp/terraform-provider-vault/internal/vault/generic

$ go test ./internal/framework/validators/...
ok  github.com/hashicorp/terraform-provider-vault/internal/framework/validators
```

`TestAccGenericEndpoint_rotateRoot` is the database acceptance test carried over from the previous
action with its config switched to a full `path`. It independently rotated the Postgres password —
confirmed by the old password failing after the suite finished.

The `TestRotateRootPath` unit test from the previous design was deleted along with the
`rotateRootPath()` helper. It asserted the provider assembled paths correctly for six engines;
the provider no longer assembles paths.

## 7. Not executed

| Engine | Path | Blocked by |
|---|---|---|
| Azure | `{mount}/rotate-root` | Needs a live Azure AD app registration |
| GCP | `{mount}/config/rotate-root` | Needs a live GCP service account |
| Active Directory | `{mount}/rotate-root` | Needs a live domain controller |
| Enterprise namespaces | any | Vault CE used for this run — see [F2](#f2) |

These are lower risk than under the previous design. The provider no longer branches on engine at
all: it writes the string it is given. P1, P3, P4 and P5 together show that a user-supplied path
of any shape, with or without a body, reaches Vault unmodified. What remains untested for these
engines is Vault's own rotation behaviour, not this provider change.

## 8. Audit evidence

14 relevant entries captured; 8 successful writes and 6 expected errors.

```
15:05:26  mt1-database/rotate-root/postgres     ok   # P1
15:05:45  mt-ldap/rotate-root                   ok   # P3
15:06:07  mt-ldap/rotate-root                   ok   # P3 second rotation
15:06:19  mt-aws/config/rotate-root             ok   # P4
15:06:38  sys/policies/acl/tf-action-test       ok   # P5
15:07:19  mt1-database/rotate-root/postgres     ok   # N12 (namespace ignored on CE)
```

## 9. Summary

| Area | Result |
|---|---|
| Database (PostgreSQL) live rotation | PASS |
| LDAP live rotation | PASS |
| AWS live rotation | PASS |
| Non-rotation endpoint with `data_json` | PASS |
| `after_create` fires once only | PASS |
| Negative / validation cases (14) | 12 PASS, 1 PARTIAL (F1), 1 behaviour finding (F2) |
| Automated tests | PASS |
| Azure / GCP / AD | Not executed — provider no longer branches on engine |

No functional defects. The findings are documentation and error-message matters; F2 and F3 are
addressed in the action docs, F1 partially, F4 outstanding.
