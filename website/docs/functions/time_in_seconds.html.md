---
layout: "vault"
page_title: "Vault: time_in_seconds function"
sidebar_current: "docs-vault-function-time-in-seconds"
description: |-
  Convert a Vault duration string to an integer number of seconds.
---

# time_in_seconds

`time_in_seconds` converts a Vault duration string into an integer number of seconds.

Provider functions require Terraform 1.8 or later.

Accepted formats:

* Go duration units: `ns`, `us` (or `µs`), `ms`, `s`, `m`, and `h`. For example, `"1h"` or `"90m"`.
* A `d` suffix for days. For example, `"3d"`.
* A bare integer, which is a number of seconds. For example, `"3600"`.

The result is an integer. A negative duration, or a duration that is not a whole number of seconds, returns an error.

## Example Usage

```hcl
terraform {
  required_version = ">= 1.8.0"
  required_providers {
    vault = {
      source = "hashicorp/vault"
    }
  }
}

output "example_output" {
  value = provider::vault::time_in_seconds("1h")
}
```

## Signature

```text
time_in_seconds(duration string) number
```

## Arguments

1. `duration` (String) Vault duration string to parse. The result is an integer number of seconds.
