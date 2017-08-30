## 0.1.1 (Unreleased)

BACKWARDS INCOMPATIBILITIES / NOTES:
* `vault_auth_backend`'s ID has changed from the `type` to the `path` of the auth backend.
  Interpolations referring to the `.id` of a `vault_auth_backend` should be updated to use
  its `.type` property. [GH-12]

FEATURES:

IMPROVEMENTS:
* `vault_auth_backend`s are now importable. [GH-12]
* `vault_policy`s are now importable [GH-15]
* `vault_mount`s are now importable [GH-16]

BUG FIXES:

## 0.1.0 (June 21, 2017)

NOTES:

* Same functionality as that of Terraform 0.9.8. Repacked as part of [Provider Splitout](https://www.hashicorp.com/blog/upcoming-provider-changes-in-terraform-0-10/)
