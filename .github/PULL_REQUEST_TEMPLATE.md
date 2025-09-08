<!--- See what makes a good Pull Request at : https://github.com/hashicorp/terraform-provider-vault/blob/master/.github/CONTRIBUTING.md --->


### Description
<!--- Description of the change. For example: This PR updates ABC resource so that we can XYZ --->


<!--- If your PR fully resolves and should automatically close the linked issue, use Closes. Otherwise, use Relates --->
Relates OR Closes #0000


### Checklist
- [ ] Added [CHANGELOG](https://github.com/hashicorp/terraform-provider-vault/blob/master/CHANGELOG.md) entry (only for user-facing changes)
- [ ] Acceptance tests where run against all supported Vault Versions


### Output from acceptance testing:

```
$ make testacc TESTARGS='-run=TestAccXXX'

...
```


<!--- Please keep this note for the community --->

### Community Note

* Please vote on this pull request by adding a 👍 [reaction](https://blog.github.com/2016-03-10-add-reactions-to-pull-requests-issues-and-comments/) to the original pull request comment to help the community and maintainers prioritize this request
* Please do not leave "+1" comments, they generate extra noise for pull request followers and do not help prioritize the request

<!--- Thank you for keeping this note for the community --->


## PCI review checklist

<!-- heimdall_github_prtemplate:grc-pci_dss-2024-01-05 -->

- [ ] I have documented a clear reason for, and description of, the change I am making.

- [ ] If applicable, I've documented a plan to revert these changes if they require more than reverting the pull request.

- [ ] If applicable, I've documented the impact of any changes to security controls.

  Examples of changes to security controls include using new access control methods, adding or removing logging pipelines, etc.
