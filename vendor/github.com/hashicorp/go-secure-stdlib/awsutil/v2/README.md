# AWSUTIL - Go library for generating aws credentials

*NOTE*: This is version 2 of the library. The `v0` branch contains version 0,
which may be needed for legacy applications or while transitioning to version 2.

## Usage

Following is an example usage of generating AWS credentials with static user credentials

```go

// AWS access keys for an IAM user can be used as your AWS credentials.
// This is an example of an access key and secret key
var accessKey = "AKIAIOSFODNN7EXAMPLE"
var secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

// Access key IDs beginning with AKIA are long-term access keys. A long-term
// access key should be supplied when generating static credentials.
config, err := awsutil.NewCredentialsConfig(
    awsutil.WithAccessKey(accessKey),
    awsutil.WithSecretKey(secretKey),
)
if err != nil {
    return err
}

s3Client := s3.NewFromConfig(config)

```

## Contributing to v0

To push a bug fix or feature for awsutil `v0`, branch out from the [awsutil/v0](https://github.com/hashicorp/go-secure-stdlib/tree/awsutil/v0) branch.
Commit the code changes you want to this new branch and open a PR. Make sure the PR
is configured so that the base branch is set to `awsutil/v0` and not `main`. Once the PR
is reviewed, feel free to merge it into the `awsutil/v0` branch. When creating a new
release, validate that the `Target` branch is `awsutil/v0` and the tag is `awsutil/v0.x.x`.