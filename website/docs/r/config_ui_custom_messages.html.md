---
layout: "vault"
page_title: "Vault: vault_config_ui_custom_message resource"
sidebar_current: "docs-vault-resource-config-ui-custom-message"
description: |-
  Manages a UI custom message in Vault.
---

# vault\_config\_ui\_custom\_message

Manages a UI custom message in Vault. Custom messages are displayed in the Vault UI either on the login page or immediately after succesfully logging in.

**Note** this feature is available only with Vault Enterprise.

## Example Usage

```hcl
resource "vault_config_ui_custom_message" "maintenance" {
  title          = "Upcoming maintenance"
  message_base64 = base64encode("Vault will be offline for planned maintenance on February 1st, 2024 from 05:00Z to 08:00Z")
  type           = "banner"
  authenticated  = true
  start_time     = "2024-01-01T00:00:00.000Z"
  end_time       = "2024-02-01T05:00:00.000Z"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `title` - (Required) The title of the custom message to create.

* `message_base64` - (Required) The base64-encoded content of the custom message.

* `start_time` - (Required) The time when the custom message begins to be active. This value can be set to a future time, but cannot
   occur on or after the `end_time` value.

* `authenticated` - (Optional) The value `true` if the custom message is displayed after logins are completed or `false` if they are
   displayed during the login in the Vault UI. The default value is `true`.

* `type` - (Optional) The presentation type of the custom message. Must be one of the following values: `banner` or `modal`.

* `end_time` - (Optional) The time when the custom message expires. If this value is not specified, the custom message never expires.

* `link` - (Optional) A hyperlink to be included with the message. [See below for more details](#link).

* `options` - (Optional) A map of additional options that can be set on the custom message.

### Link

* `title` - (Required) The hyperlink title that is displayed in the custom message.

* `href` - (Required) The URL set in the hyperlink's href attribute.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Custom messages can be imported using their `id` e.g.

```
$ terraform import vault_config_ui_custom_message.maintenance df773ef1-2794-45d3-9e25-bcccffe4dbde
```
