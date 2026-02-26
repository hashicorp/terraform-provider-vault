## v0.15.0
### May 30, 2025

### IMPROVEMENTS
* Bump Go version to 1.24.3
* update dependencies
    * `github.com/go-ldap/ldap/v3` v3.4.10 -> v3.4.11\
    * `github.com/hashicorp/vault/sdk` v0.15.0 -> v0.17.0
    * `github.com/ory/dockertest/v3` v3.11.0 -> v3.12.0
    * `github.com/go-jose/go-jose/v4` v4.0.4 -> v4.0.5
    * `github.com/opencontainers/runc` v1.2.0 -> v1.2.6
    * `golang.org/x/crypto` v0.32.0 -> v0.36.0
    * `golang.org/x/net` v0.34.0 -> v0.37.0

## v0.14.0
### February 12, 2025

### IMPROVEMENTS
* Bump Go version to 1.23.6
* update dependencies
  * `github.com/go-ldap/ldap/v3` v3.4.8 -> v3.4.10
  * `github.com/hashicorp/vault/api` v1.14.0 -> v1.16.0
  * `github.com/hashicorp/vault/sdk` v0.13.0 -> v0.15.0
  * `github.com/ory/dockertest/v3` v3.10.0 -> v3.11.0

## v0.13.0
### September 3, 2024

### IMPROVEMENTS
* Bump Go version to 1.22.6
* update dependencies
  * `github.com/docker/docker v25.0.5+incompatible` -> v25.0.6+incompatible
  * `github.com/hashicorp/go-retryablehttp v0.7.6` -> v0.7.7
  * `github.com/hashicorp/vault/api` v1.13.0 -> v1.14.0
  * `github.com/hashicorp/vault/sdk` v0.12.0 -> v0.13.0

## v0.12.0
### May 21, 2024

### IMPROVEMENTS
* update dependencies

* `github.com/go-ldap/ldap/v3` v3.4.4 -> v3.4.8
* `github.com/hashicorp/go-hclog` v1.6.2 -> v1.6.3
* `github.com/hashicorp/vault/api` v1.11.0 -> v1.13.0
* `github.com/hashicorp/vault/sdk` v0.10.2 -> v0.12.0

## v0.11.0

### IMPROVEMENTS
* update dependencies
  * `github.com/go-ldap/ldap/v3` v3.4.4 -> v3.4.6
  * `github.com/hashicorp/go-hclog` v1.5.0 -> v1.6.2
  * `github.com/hashicorp/vault/api` v1.9.2 -> v1.11.0
  * `github.com/hashicorp/vault/sdk` v0.9.2 -> v0.10.29.2

## v0.10.1

### IMPROVEMENTS
* update dependencies
  * `github.com/hashicorp/vault/api` v1.9.2
  * `github.com/hashicorp/vault/sdk` v0.9.2

## v0.10.0

### IMPROVEMENTS

* enable plugin multiplexing [GH-82](https://github.com/hashicorp/vault-plugin-auth-kerberos/pull/82)
* update dependencies
  * `github.com/hashicorp/vault/api` v1.9.0
  * `github.com/hashicorp/vault/sdk` v0.8.1

## v0.9.0

### IMPROVEMENTS

* Update dependencies
  * Update gokbr5 lib [[GH-77](https://github.com/hashicorp/vault-plugin-auth-kerberos/pull/77)]
  * Update github.com/hashicorp/vault/sdk [[GH-81](https://github.com/hashicorp/vault-plugin-auth-kerberos/pull/81)]
  * Update github.com/hashicorp/vault/api [[GH-81](https://github.com/hashicorp/vault-plugin-auth-kerberos/pull/81)]
* Remove CreateOperation [[GH-79](https://github.com/hashicorp/vault-plugin-auth-kerberos/pull/79)]
  * This change is transparent to users.

## v0.8.0

* Plugin release milestone

## v0.7.3

### IMPROVEMENTS

* Add config parameter to include group aliases found in LDAP [[GH-73](https://github.com/hashicorp/vault-plugin-auth-kerberos/pull/73)]

## v0.7.2

### BUG FIXES

* Maintain headers set by the client [[GH-61](https://github.com/hashicorp/vault-plugin-auth-kerberos/pull/61)]

## v0.7.1

### IMPROVEMENTS

* Add remove_instance_name config to CLI and mount config  [[GH-68](https://github.com/hashicorp/vault-plugin-auth-kerberos/pull/68)]
