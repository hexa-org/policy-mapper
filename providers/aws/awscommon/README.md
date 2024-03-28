![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Amazon Providers - Shared AWS Http Client awscommon

The `awscommon` package is used by all AWS based providers.

This package is used to parse an AWS access key from `policyprovider.IntegrationInfo` and return an `aws.Config` struct. It also
defines an HTTPClient which can be used to establish testing overrides.