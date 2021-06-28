Terraform Provider
==================

- Website: https://www.terraform.io
- [![Gitter chat](https://badges.gitter.im/hashicorp-terraform/Lobby.png)](https://gitter.im/hashicorp-terraform/Lobby)
- Mailing list: [Google Groups](http://groups.google.com/group/terraform-tool)

<img src="https://cdn.rawgit.com/hashicorp/terraform-website/master/content/source/assets/images/logo-hashicorp.svg" width="600px">

Maintainers
-----------

This provider plugin is maintained by the Vault team at [HashiCorp](https://www.hashicorp.com/).

Best Practices
--------------

We recommend that you avoid placing secrets in your Terraform config or state file wherever possible, and if placed there, you take steps to reduce and manage your risk. We have created a practical guide on how to do this with our opensource versions in Best Practices for Using HashiCorp Terraform with HashiCorp Vault:

[![Best Practices for Using HashiCorp Terraform with HashiCorp Vault](https://img.youtube.com/vi/fOybhcbuxJ0/0.jpg)](https://www.youtube.com/watch?v=fOybhcbuxJ0)

This webinar walks you through how to protect secrets when using Terraform with Vault. Additional security measures are available in paid Terraform versions as well.

Requirements
------------

-	[Terraform](https://www.terraform.io/downloads.html) 0.11.x
-	[Go](https://golang.org/doc/install) 1.16 (to build the provider plugin)

Building The Provider
---------------------

Clone repository to: `$GOPATH/src/github.com/hashicorp/terraform-provider-vault`

```sh
$ mkdir -p $GOPATH/src/github.com/hashicorp; cd $GOPATH/src/github.com/hashicorp
$ git clone git@github.com:hashicorp/terraform-provider-vault
```

Enter the provider directory and build the provider

```sh
$ cd $GOPATH/src/github.com/hashicorp/terraform-provider-vault
$ make build
```

Using the provider
----------------------

Developing the Provider
---------------------------

If you wish to work on the provider, you'll first need [Go](http://www.golang.org) installed on your machine (version 1.16+ is *required*). You'll also need to correctly setup a [GOPATH](http://golang.org/doc/code.html#GOPATH), as well as adding `$GOPATH/bin` to your `$PATH`.

To compile the provider, run `make build`. This will build the provider and put the provider binary in the `$GOPATH/bin` directory.

```sh
$ make build
...
$ $GOPATH/bin/terraform-provider-vault
...
```

In order to test the provider, you can simply run `make test`.

```sh
$ make test
```

In order to run the full suite of Acceptance tests, you will need the following:

*Note:* Acceptance tests create real resources, and often cost money to run.

1. An instance of Vault running to run the tests against
2. The following environment variables are set:
    - `VAULT_ADDR` - location of Vault
    - `VAULT_TOKEN` - token used to query Vault. These tests do not attempt to read `~/.vault-token`.
3. The following environment variables may need to be set depending on which acceptance tests you wish to run.
There may be additional variables for specific tests. Consult the specific test(s) for more information.
    - `AWS_ACCESS_KEY_ID`
    - `AWS_SECRET_ACCESS_KEY`
    - `GOOGLE_CREDENTIALS`
    - `GOOGLE_PROJECT`
    - `RMQ_CONNECTION_URI`
    - `RMQ_USERNAME`
    - `RMQ_PASSWORD`
    - `ARM_SUBSCRIPTION_ID`
    - `ARM_TENANT_ID`
    - `ARM_CLIENT_ID`
    - `ARM_CLIENT_SECRET`
    - `ARM_RESOURCE_GROUP`
4. Run `make testacc`

If you wish to run specific tests, use the `TESTARGS` environment variable:

```sh
TESTARGS="--run DataSourceAWSAccessCredentials" make testacc
```
