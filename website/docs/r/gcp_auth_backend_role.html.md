---
layout: "vault"
page_title: "Vault: vault_gcp_auth_backend_role resource"
sidebar_current: "docs-vault-resource-gcp-auth-backend-role"
description: |-
  Managing roles in an GCP auth backend in Vault
---

# vault\_gcp\_auth\_backend\_role

Provides a resource to create a role in an [GCP auth backend within Vault](https://www.vaultproject.io/docs/auth/gcp.html).

## Example Usage

```hcl
resource "vault_auth_backend" "gcp" {
    path = "gcp"
    type = "gcp"
}

resource "vault_gcp_auth_backend_role" "gcp" {
    backend                = vault_auth_backend.gcp.path
    project_id             = "foo-bar-baz"
    bound_service_accounts = ["database-server@foo-bar-baz.iam.gserviceaccount.com"]
    token_policies         = ["database-server"]

}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `role` - (Required) Name of the GCP role

* `type` - (Required) Type of GCP authentication role (either `gce` or `iam`)

* `bound_projects` - (Optional) An array of GCP project IDs. Only entities belonging to this project can authenticate under the role.

* `backend` - (Optional) Path to the mounted GCP auth backend

* `bound_service_accounts` - (Optional) GCP Service Accounts allowed to issue tokens under this role. (Note: **Required** if role is `iam`)

### `iam`-only Parameters

* `max_jwt_exp` - (Optional) The number of seconds past the time of authentication that the login param JWT must expire within. For example, if a user attempts to login with a token that expires within an hour and this is set to 15 minutes, Vault will return an error prompting the user to create a new signed JWT with a shorter `exp`. The GCE metadata tokens currently do not allow the `exp` claim to be customized.

* `allow_gce_inference` - (Optional) A flag to determine if this role should allow GCE instances to authenticate by inferring service accounts from the GCE identity metadata token.

### `gce`-only Parameters

The following parameters are only valid when the role is of type `"gce"`:

* `bound_zones` - (Optional)  The list of zones that a GCE instance must belong to in order to be authenticated. If bound_instance_groups is provided, it is assumed to be a zonal group and the group must belong to this zone.

* `bound_regions` - (Optional) The list of regions that a GCE instance must belong to in order to be authenticated. If bound_instance_groups is provided, it is assumed to be a regional group and the group must belong to this region. If bound_zones are provided, this attribute is ignored.

* `bound_instance_groups` - (Optional) The instance groups that an authorized instance must belong to in order to be authenticated. If specified, either `bound_zones` or `bound_regions` must be set too.

* `bound_labels` - (Optional) A comma-separated list of GCP labels formatted as `"key:value"` strings that must be set on authorized GCE instances. Because GCP labels are not currently ACL'd, we recommend that this be used in conjunction with other restrictions.

* `bound_projects` - (Optional) GCP Projects that the role exists within

For more details on the usage of each argument consult the [Vault GCP API documentation](https://www.vaultproject.io/api-docs/auth/gcp).

### Common Token Arguments

These arguments are common across several Authentication Token resources since Vault 1.2.

* `token_ttl` - (Optional) The incremental lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_max_ttl` - (Optional) The maximum lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_period` - (Optional) If set, indicates that the
  token generated using this role should never expire. The token should be renewed within the
  duration specified by this value. At each renewal, the token's TTL will be set to the
  value of this field. Specified in seconds.

* `token_policies` - (Optional) List of policies to encode onto generated tokens. Depending
  on the auth method, this list may be supplemented by user/group/other values.

* `token_bound_cidrs` - (Optional) List of CIDR blocks; if set, specifies blocks of IP
  addresses which can authenticate successfully, and ties the resulting token to these blocks
  as well.

* `token_explicit_max_ttl` - (Optional) If set, will encode an
  [explicit max TTL](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token in number of seconds. This is a hard cap even if `token_ttl` and
  `token_max_ttl` would otherwise allow a renewal.

* `token_no_default_policy` - (Optional) If set, the default policy will not be set on
  generated tokens; otherwise it will be added to the policies set in token_policies.

* `token_num_uses` - (Optional) The [maximum number](https://www.vaultproject.io/api-docs/gcp#token_num_uses)
   of times a generated token may be used (within its lifetime); 0 means unlimited.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

## Attribute Reference

No additional attributes are exposed by this resource.


## Import

GCP authentication roles can be imported using the `path`, e.g.

```
$ terraform import vault_gcp_auth_backend_role.my_role auth/gcp/role/my_role
```
