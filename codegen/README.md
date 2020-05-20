# Generating Resources and Data Sources

This code is part of a code generation package. It is intended to speed 
up development while still yielding high quality code.

## How to Generate Code and Docs
- Please only PR 1 newly generated endpoint at a time to keep PRs small and focused.
- Ensure `testdata/openapi.json` includes the endpoints for which you want to generate code.
- If it doesn't:
  - Make a new Vault dev binary from the `vault-enterprise` repo.
  - Export a Vault license that includes the `transform` secrets engine: `export VAULT_LICENSE=foo`.
  - In the Vault or Vault Enterprise repo, run `bash scripts/gen_openapi.sh`.
  - Move the resulting file to `testdata/openapi.json`.
- Add the 1 endpoint you wish to generate to `codegen/endpoint_registry.go`.
- From the home directory of `terraform-provider-vault`, run:
```
make generate
```
- If you note any changes, you may need to hand-add code that implements 
[best practices](https://www.terraform.io/docs/extend/best-practices/deprecations.html)
for deprecations.
- Hand-test the code while comparing it to Vault's API docs until you're satisfied that
the generated code is correct.
- Also check against the real Vault API. The OpenAPI doc _does not_ include all response
parameters, nor do Vault docs, and some response parameters are returned conditionally. 
So, play with the endpoint and verify you've accounted for all the parameters coming out 
of it.
- If you find undocumented response parameters, add them to the endpoint's `additionalInfo`.
- Hand-write unit tests for the code.
- Hand-add the new resource or data source to `generated/terraform_registry.go`.
- Hand update the partially generated doc to complete it.
- Add the doc to the sidebar/layout so it will appear in nav.
