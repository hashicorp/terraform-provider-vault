---
layout: "vault"
page_title: "Vault: time_in_seconds function"
sidebar_current: "docs-vault-function-time-in-seconds"
description: |-
  Convert a Go duration string to a number of seconds.
---

# time_in_seconds

Given a [Go duration string](https://pkg.go.dev/time#ParseDuration), `time_in_seconds` returns that duration as a number of seconds.

Provider functions require Terraform 1.8 or later. The units are `ns`, `us` (or `µs`), `ms`, `s`, `m`, and `h`. `"3d"` is not a valid duration string.

The result is a number. A whole number, such as `time_in_seconds("1h")`, can be assigned to an integer-seconds argument.

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

1. `duration` (String) Go time package duration string to parse.
