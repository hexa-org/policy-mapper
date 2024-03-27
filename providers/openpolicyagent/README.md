![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Open Policy Agent Provider

The Open Policy Agent Provider enables the retrieval and provisioning of IDQL policies to an [Open Policy Agent](https://www.openpolicyagent.org) environment.

> [!Tip]
> For full support of IDQL conditions, use the extended OPA server found in the sister [Policy-OPA](https://github.com/hexa-org/policy-opa) project.

| Feature           | Description                                                                                                | Platform Support                           | Provider Support                   |
|-------------------|------------------------------------------------------------------------------------------------------------|--------------------------------------------|------------------------------------|
| RBAC              | Support for basic translation of role-based access policy                                                  | Yes                                        | Yes                                |
| ABAC              | Support for attribute conditions                                                                           | Yes                                        | Yes                                |
| Type              | IDQL Native. Policy is interpreted by OPA Rego processor.                                                  | Rego                                       | Deployment of IDQL and Rego policy |
| Attribute Mapping | Attribute names in policy can be mapped to platform                                                        |                                            | Yes                                |
| Hexa CLI      | Supported in the Hexa CLI application                                                                  |                                            | Yes                                |
| Discovery         | Supports discovery of Policy Application Points                                                            | Queries IAP Backend and AppEngine services | Yes                                |
| Get Policies      | Supports retrieval of all policies from a PAP                                                              | Yes                                        | Yes                                |
| Set Policies      | Supports the ability to apply a set of policies to a PAP                                                   | Yes                                        |
| Reconcile         | Returns the differences between an existing set of policies (e.g. at the source) and another set (updates) | Via pkg/hexaPolicy                         | Yes                                |

## How IDQL and OPA works 

This provider works by assembling a Rego script for processing IDQL (hexaPolicy.rego) and IDQL policy (data.json) as a bundle 
that can be provisioned to an OPA server via a bundle pick-up point. Currently 4 bundle service types are implemented: 
* Google Cloud Storage,
* Amazon S3 Storage, 
* Github Repository, and,
* HTTP Server 

To support IDQL Conditions, a HexaFilter extension is provided that may be installed in the OPA server. For more 
information, see the [Hexa Policy-OPA project](https://github.com/hexa-org/policy-opa).

## Integration Support Notes

In the Hexa CLI, adding an OPA integration takes the form:
```shell
hexa add opa http myBundle --file=integration.json
```

Or, parameters can be passed with flags (e.g. --url and --cafile)
```shell
hexa add opa http myBundle --url="https://hexa-bundle-server:8889" --cafile="./examples/opa-server/.certs/ca-cert.pem"
```

In the SDK, typically the same JSON file may be passed to the SDK as follows:
```go
package main

import (
    "encoding/json"
    "fmt"
    "os"

    "github.com/hexa-org/policy-mapper/api/policyprovider"
    "github.com/hexa-org/policy-mapper/sdk"
)

func main() {
    
    // Read the integration.json file and insert as the Key...
    keybytes, err := os.ReadFile("integration.json")
    if err != nil {
        panic(-1)
    }

    info := policyprovider.IntegrationInfo{
        Name: sdk.ProviderTypeOpa,
        Key:  keybytes,
    }

    integration, err := sdk.OpenIntegration(&info)
    if err != nil {
        fmt.Println("Error opening integration: " + err.Error())
        panic(-1)
    }

    . . .

}
```

### Integration Key File Examples

Integration Configuration For **Google Cloud Storage**:
```json
{
  "gcp": {
    "bucket_name": "BUCKET_NAME",
    "object_name": "bundle.tar.gz",
    "key": {
      "type": "service_account",
      "project_id": "google-cloud-project-id",
      "private_key_id": "",
      "private_key": "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
      "client_email": "google-cloud-project-id@google-cloud-project-id.iam.gserviceaccount.com",
      "client_id": "000000000000000000000",
      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
      "token_uri": "https://oauth2.googleapis.com/token",
      "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
      "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/google-cloud-project-id%google-cloud-project-id.iam.gserviceaccount.com"
    }
  }
}
```

Integration with **Amazon S3 Storage**:
The key must allow [s3:PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html)
and [s3.GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html) actions.
```json
{
  "aws": {
    "bucket_name": "aws-s3-bucket-name",
    "object_name": "bundle.tar.gz",
    "key": {
      "region": "aws-region",
      "accessKeyID": "00000000000000000000",
      "secretAccessKey": "99999999999999999999999"
    }
  }
}
```

Integration with Github:

To integrate with Github, create a [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token#creating-a-personal-access-token-classic) (classic).
Must allow `read:packages`, `write:packages`.

```json
{
  "github": {
    "account": "github-org-or-account",
    "repo": "github-repo",
    "bundlePath": "bundle.tar.gz",
    "key": {
      "accessToken": "github_personal_access_token_classic"
    }
  }
}
```

Integration for HTTP:
```json
{
  "bundle_url": "https://hexa-bundle-server",
  "ca_cert": "MIIFbTCCA1WgAwIBAgICB+MwDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMx ... y9NWifDJgUtx887LJA=="
}
```

The ca_cert is a PEM encoded public key.  This is used to authenticate the bundle_url endpoint. Generally this is needed 
when using self-signed certificates.