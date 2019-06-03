# Contributing

We appreciate community pull requests and have placed this guide here to help you write a complete pull request
in as few iterations as possible.

`terraform-provider-vault` is a custom provider and an extension of Terraform. As such, Terraform's guide to
[Extending Terraform](https://www.terraform.io/docs/extend/index.html) is a fantastic tool for writing new resources. 
It includes code samples, a guide on how to write tests using the test framework, how rename and deprecate attributes, 
and much more.

A PR that's ready for review has the following components:

- The code that's being changed, aligned with the guide to Extending Terraform.
- Acceptance tests that cover the code's sunny path for all changed fields.
- Updated docs.
- A link to any issues the PR closes, though it isn't required that a PR be related to an open issue.
- Go mod is used to update dependencies through running `$ GO111MODULE=on`, `$ go test ./...`, `$ go mod vendor`, and maybe a `$ go mod tidy` for good measure. 

We review PRs on a periodic basis rather than immediately.

Thank you!

:+1::tada:
