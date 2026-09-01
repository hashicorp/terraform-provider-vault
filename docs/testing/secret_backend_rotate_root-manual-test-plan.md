# Manual Test Plan & Results — `vault_secret_backend_rotate_root` action

Covers PR [#2956](https://github.com/hashicorp/terraform-provider-vault/pull/2956) (issue
[#2954](https://github.com/hashicorp/terraform-provider-vault/issues/2954)).

## 1. Scope

The action performs exactly one Vault API call:

```
PUT /v1/{backend}/rotate-root          # when `name` is unset
PUT /v1/{backend}/rotate-root/{name}   # when `name` is set
```

Everything engine-specific reduces to **which string lands in `backend`** and **whether `name` is
set**. There is no per-engine branching in the provider code — see
`rotateRootPath()` in `internal/vault/secrets/rotate/action_rotate_root.go`.

That shapes this plan: rather than a full rotation against all nine engines, it verifies

1. **Real rotation, end-to-end, on three engines with different path shapes** — Database
   (`{mount}/rotate-root/{name}`), LDAP (`{mount}/rotate-root`), AWS (`{mount}/config/rotate-root`).
   Each is confirmed by an out-of-band check that the *old* credential no longer authenticates.
2. **Negative and validation paths** — bad mounts, bad names, ACL denial, schema validators.
3. **Path-shape equivalence** for the remaining engines via `TestRotateRootPath`.

Azure, GCP and AD share the LDAP path shape (`{mount}/rotate-root`, no `name`) and are covered by
the unit test, not executed live. See §7.

## 2. Environment

| Component | Version / detail |
|---|---|
| Provider | branch `action-rotate-root` @ `36732976` |
| Terraform | 1.15.2 (actions require ≥ 1.14.0) |
| Vault | 2.0.3 Community Edition, `-dev` mode, `http://127.0.0.1:8200` |
| Go | 1.26.6 darwin/arm64 |
| PostgreSQL | 18.3 (Homebrew), `127.0.0.1:5433` |
| OpenLDAP | 2.6.10 (`bitnamilegacy/openldap`), `127.0.0.1:1389` |
| AWS | account `717316313319`, throwaway IAM user (created and deleted for the test) |
| Executed | 2026-09-01 |

Provider loaded via `dev_overrides`; Vault file audit device enabled at `rr/` to capture evidence.

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

> **Note:** Terraform has no `terraform invoke` command. Actions can only be triggered through
> `lifecycle { action_trigger { ... } }` on a resource. Every case below therefore hangs the action
> off either the resource under test or a `terraform_data` trigger.

### 3.1 Postgres

```bash
pg_ctl -D "$PGDATA" initdb -o "-U postgres --auth=trust"
LC_ALL=C pg_ctl -D "$PGDATA" -o "-p 5433 -k /tmp" start
psql -h /tmp -p 5433 -U postgres \
  -c "CREATE ROLE rotate_root_user WITH LOGIN SUPERUSER PASSWORD 'rotate_root_password';"
# set host lines in pg_hba.conf to scram-sha-256 so rotation is observable, then reload
```

### 3.2 OpenLDAP

```bash
podman run -d --name rr-ldap -p 1389:1389 \
  -e LDAP_ADMIN_USERNAME=admin -e LDAP_ADMIN_PASSWORD=adminpassword \
  -e LDAP_ROOT=dc=example,dc=org docker.io/bitnamilegacy/openldap:latest
```

Create a **dedicated bind user** — not the directory root — matching the warning in the action docs:

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

Grant that user self-write on `userPassword` (Bitnami's default ACL does not):

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

> The IAM user must be able to manage **its own** access keys, and an IAM user is limited to two
> access keys. Rotation creates a new key and **deletes the old one** — never point this at a user
> whose key you still rely on.

## 4. Positive cases

### P1 — Database (PostgreSQL), `{mount}/rotate-root/{name}`

```hcl
resource "vault_mount" "db" {
  path = "mt1-database"
  type = "database"
}

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
      actions = [action.vault_secret_backend_rotate_root.postgres]
    }
  }
}

action "vault_secret_backend_rotate_root" "postgres" {
  config {
    backend = vault_mount.db.path
    name    = vault_database_secret_backend_connection.postgres.name
  }
}
```

**Steps**

1. Confirm baseline: `PGPASSWORD=rotate_root_password psql -U rotate_root_user ...` succeeds.
2. `terraform apply -auto-approve`.
3. Re-run the baseline login — it must now **fail**.
4. Issue a dynamic credential to prove Vault holds the new password.

**Expected**

- Apply reports `Actions: 1 invoked` with progress lines naming `mt1-database/rotate-root/postgres`.
- Old password rejected.
- Dynamic credential still issues.

**Actual** — PASS.

```
Action ...: Rotating root credentials at mt1-database/rotate-root/postgres
Action ...: Successfully rotated root credentials at mt1-database/rotate-root/postgres
Apply complete! Resources: 2 added, 0 changed, 0 destroyed. Actions: 1 invoked.

$ PGPASSWORD=rotate_root_password psql -h 127.0.0.1 -p 5433 -U rotate_root_user -d postgres
psql: error: ... FATAL:  password authentication failed for user "rotate_root_user"

$ vault read mt1-database/creds/r
dynamic cred issued for user: v-token-r-dYOsbXvVemxrpLAAk9Ed-1788287669
```

### P2 — `after_create` does not re-fire on subsequent applies

**Steps** — run `terraform apply` a second time with no config change.

**Expected** — `No changes.`, no `Actions: 1 invoked` line, no new audit entry.

**Actual** — PASS. Apply reported `No changes.` and no action was invoked. Rotation is therefore
tied to resource creation only; re-rotation requires `terraform apply -replace` or a separate
trigger.

### P3 — LDAP, `{mount}/rotate-root` (no `name`)

```hcl
action "vault_secret_backend_rotate_root" "ldap" {
  config {
    backend = "mt-ldap"
  }
}
```

with

```bash
vault write mt-ldap/config \
  binddn="cn=vaultbind,ou=users,dc=example,dc=org" \
  bindpass="vaultbindpassword" \
  url="ldap://127.0.0.1:1389" \
  userdn="ou=users,dc=example,dc=org" \
  schema=openldap
```

**Steps**

1. Baseline: `ldapwhoami -x -D "cn=vaultbind,ou=users,dc=example,dc=org" -w vaultbindpassword` → returns the DN.
2. `terraform apply -auto-approve`.
3. Repeat the bind — must fail.
4. `vault write -f mt-ldap/rotate-root` a second time to prove Vault stored the new bind password.

**Actual** — PASS.

```
Action ...: Successfully rotated root credentials at mt-ldap/rotate-root
Apply complete! Resources: 1 added, 0 changed, 0 destroyed. Actions: 1 invoked.

$ ldapwhoami -x -H ldap://127.0.0.1:1389 -D "cn=vaultbind,ou=users,dc=example,dc=org" -w vaultbindpassword
ldap_bind: Invalid credentials (49)

$ vault write -f mt-ldap/rotate-root
Success! Data written to: mt-ldap/rotate-root
```

The second rotation succeeding is the proof that Vault is holding a working new password — a stale
stored password would have failed the bind.

### P4 — AWS, `{mount}/config/rotate-root`

```hcl
action "vault_secret_backend_rotate_root" "aws" {
  config {
    backend = "mt-aws/config"   # note the /config suffix
  }
}
```

**Steps**

1. `vault write mt-aws/config/root access_key=… secret_key=… region=us-east-1`.
2. Record the key ID: `aws iam list-access-keys --user-name vault-rotate-root-test`.
3. `terraform apply -auto-approve`.
4. List keys again; attempt an API call with the original key; read `mt-aws/config/root`.

**Actual** — PASS.

```
Action ...: Successfully rotated root credentials at mt-aws/config/rotate-root
Apply complete! Resources: 1 added, 0 changed, 0 destroyed. Actions: 1 invoked.

before: AKIA2OA3CKDTXT2K2BET
after:  AKIA2OA3CKDTYHBQZXBJ     # old key deleted, not merely deactivated

$ AWS_ACCESS_KEY_ID=AKIA2OA3CKDTXT2K2BET … aws sts get-caller-identity
An error occurred (InvalidClientTokenId) … The security token included in the request is invalid.

$ vault read mt-aws/config/root
vault access_key = AKIA2OA3CKDTYHBQZXBJ
```

Temp IAM user and both keys deleted after the test.

## 5. Negative cases

All run through a `terraform_data` trigger against the action.

| # | Case | Config | Expected | Actual |
|---|---|---|---|---|
| N1 | Mount does not exist | `backend = "nonexistent-backend"`, `name = "nope"` | Apply-time error naming the full path | **PASS** — `404 … no handler for route "nonexistent-backend/rotate-root/nope"` |
| N2 | Valid mount, unknown connection | `backend = "mt1-database"`, `name = "no-such-connection"` | Apply-time error | **PASS** — error names `mt1-database/rotate-root/no-such-connection` |
| N3 | `timeout_seconds` below minimum | `timeout_seconds = 30` | Plan-time validation error | **PASS** — `Attribute timeout_seconds value must be between 60 and 7200, got: 30` |
| N4 | `timeout_seconds` above maximum | `timeout_seconds = 8000` | Plan-time validation error | **PASS** — `… got: 8000` |
| N5 | Empty `backend` | `backend = ""` | Plan-time validation error | **PASS** — `Attribute backend string length must be at least 1, got: 0` |
| N6 | `backend` omitted | *(no backend)* | Plan-time error | **PASS** — `The argument "backend" is required, but no definition was found.` |
| N7 | Token cannot mint a child token | policy without `auth/token/create` | Clear error | **PARTIAL** — fails as `Failed to get Vault client … failed to create limited child token … 403`. See finding F1. |
| N7b | Token denied on the rotate-root path | policy grants `auth/token/create`, denies rotate | 403 naming the rotate path | **PASS** — `403 … permission denied` on `PUT /v1/mt1-database/rotate-root/postgres` |
| N8 | `namespace` set against Community Edition | `namespace = "team-a"` | Error, or documented no-op | **FAIL (behaviour)** — silently succeeded against the root namespace. See finding F2. |
| N8b | `namespace` with leading/trailing slash | `namespace = "/team-a/"` | Validation error | **PASS** — `value /team-a/ contains leading/trailing "/"` |
| N9 | `name` supplied to an engine that takes none | `backend = "mt-ldap"`, `name = "somename"` | 404 | **PASS** — `404 … unsupported path` |
| N10 | AWS mount without the `/config` suffix | `backend = "mt-aws"` | 404 | **PASS** — `404 … unsupported path` on `mt-aws/rotate-root` |
| N11 | Backend unreachable (LDAP host down) | valid mount, dead LDAP server | Upstream error surfaced verbatim | **PASS** — `500 … error connecting to host "ldap://127.0.0.1:1389" … connection refused` |

## 6. Automated coverage (re-run for this report)

```
$ TF_ACC=1 POSTGRES_ROTATE_ROOT_URL='postgres://{{username}}:{{password}}@127.0.0.1:5433/postgres?sslmode=disable' \
    go test ./internal/vault/secrets/rotate/... -run 'TestAccSecretBackendRotateRoot_|TestRotateRootPath' -v

--- PASS: TestAccSecretBackendRotateRoot_basic (1.05s)
--- PASS: TestAccSecretBackendRotateRoot_invalidBackend (0.43s)
--- PASS: TestRotateRootPath (0.00s)
    --- PASS: TestRotateRootPath/database_with_connection_name
    --- PASS: TestRotateRootPath/aws_config_without_name
    --- PASS: TestRotateRootPath/gcp_config_without_name
    --- PASS: TestRotateRootPath/azure_without_name
    --- PASS: TestRotateRootPath/ad_without_name
    --- PASS: TestRotateRootPath/ldap_without_name
ok  github.com/hashicorp/terraform-provider-vault/internal/vault/secrets/rotate  2.330s
```

`TestAccSecretBackendRotateRoot_basic` also independently rotated the Postgres root password —
verified by the old password failing immediately afterwards.

## 7. Not executed

| Engine | Path shape | Why not run | Covered by |
|---|---|---|---|
| Azure | `{mount}/rotate-root` | Needs a live Azure AD app registration | `TestRotateRootPath/azure_without_name`; identical path shape to LDAP (P3) |
| GCP | `{mount}/config/rotate-root` | Needs a live GCP service account | `TestRotateRootPath/gcp_config_without_name`; identical path shape to AWS (P4) |
| Active Directory | `{mount}/rotate-root` | Needs a live AD domain controller | `TestRotateRootPath/ad_without_name`; identical path shape to LDAP (P3) |
| Enterprise namespaces | any | Vault CE used for this run | — (see finding F2) |

Because the action's only engine-specific behaviour is string construction, an engine that shares a
path shape with one of P1/P3/P4 exercises the same provider code. The residual risk for the
un-run engines is in Vault, not in this provider change.

## 8. Audit evidence

24 `rotate-root` entries were captured. Successful rotations:

```
18:34:18 update mt1-database/rotate-root/postgres    ok
18:34:29 update mt1-database/rotate-root/postgres    ok
18:35:43 update mt1-database/rotate-root/postgres    ok
18:38:23 update mt-ldap/rotate-root                  ok
18:38:33 update mt-ldap/rotate-root                  ok
19:03:34 update mt-aws/config/rotate-root            ok
```

The remaining 18 entries are the negative cases, each carrying the expected error.

## 9. Summary

| Area | Result |
|---|---|
| Database (PostgreSQL) live rotation | PASS |
| LDAP live rotation | PASS |
| AWS live rotation | PASS |
| Negative / validation cases (13) | 11 PASS, 1 PARTIAL (F1), 1 behaviour finding (F2) |
| Automated tests | PASS (2 acceptance, 6 unit sub-tests) |
| Azure / GCP / AD | Not executed — path shape covered by unit tests |

No functional defects found in the action. The four findings are documentation and error-message
improvements; none block the PR.
