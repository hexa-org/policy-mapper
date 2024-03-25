![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Hexa CLI Tool

The Hexa CLI tool uses the Hexa SDK to provision access policy to administrative APIs such as Amazon Verified Permissions, and Google Cloud Bind.

## Adding an Integration

The term `integration` refers to an administrative context usually includes a workspace or project identifier and authorization credentials to access cloud administrative APIs. To
add an integration, use the `add` command followed by a platform keyword( `avp` or `gcp` ). When adding an integration, specify the integration information using command parameters or the
--file flag to specify a configuration file. To obtain the details about a particular integration, use the help command. For example, `help add avp` returns:

```text
Usage: hexa add avp (cedar) --region=REGION --keyid=KEYID --secret=SECRET --file=FILE,... [<alias>]

Add an Amazon Verified Permissions integration

To add an Amazon AVP integration specify either a file (--file) that contains AWS credentials looks like:

    {
      "accessKeyID": "aws-access-key-id",
      "secretAccessKey": "aws-secret-access-key",
      "region": "aws-region"
    }

Or, use the parameters --region, --keyid, and --secret to specify the equivalent on the command line.

Once the AVP integration is added, it is availble for future use with the supplied alias name.

Arguments:
  [<alias>]    A new local alias that will be used to refer to the integration in subsequent operations. Defaults to an auto-generated alias

```

Example adding an Amazon AVP integration with the alias `myavp`:
```text
% hexa
hexa> add avp myavp --file=aws-cred.json

Integration of type: avp, alias: myavp successfully defined
Successfully loaded 1 policy application(s) from myavp

  PAP Alias: rKO
    ObjectId:           K21...93DH7z5
    Name:               arn:aws:verifiedpermissions::77371856:policy-store/K21...93DH7z5
    Description:        Hexa Development Store
    Service:            VerifiedPermissions
hexa>  
```
In the above example, the integration `myavp` is created and shows that one Policy Application Point was discovered and given
an alias of `rKO`.  The assigned alias is used to set, get, and reconcile policies.

## Retrieving Policies
The `get policies` command retrieves policies from the specified PAP alias and converts the results into IDQL format.

```text
hexa> get policies rKO
Policies retrieved for rKO:
{
  "policies": [
    {
      "Meta": {
        "Version": "0.6",
        "SourceData": {
          "policyType": "STATIC",
          "principal": null,
          "resource": null
        },
        "Description": "Hexa demo canary policy",
        "Created": "2023-12-26T21:45:53.558204Z",
        "Modified": "2023-12-27T22:20:18.592795Z",
        "Etag": "20-68c071fc33494d8d27b460fdae42aa1211025c24",
        "PolicyId": "KDqUKMRNEg6aEjZ6mz9dJq",
        "PapId": "K21...93DH7z5",
        "ProviderType": "avp"
      },
  . . .
```

To save policies to a file, use the --output flag as follows:
```shell
hexa> get policies rKO --output=policies.json
```
## Provisioning Policies
To provision policies to a PAP alias, use the set policies command specifying the policy file to be provisioned. If the -d option is set, the tool
will reconcile the existing policies against the policies specified in the policy file and return a report of the differences to be applied. Once confirmation is
received, the policies are applied.

> [!NOTE]
> While AVP Template Policies are mapped on retrieval using `get policies`, template policies are not currently supported for update. 

In the following example, the file policies.json contains 2 policies. The first policy has a change to the actions attribute, and the second is a policy template which is
marked as `UNSUPPORTED`.  The first policy is marked `DIF: UPDATE  [ACTION]`. This indicates that the update detected is in the IDQL Action portion. In the case of AVP,
and update is permitted. 

> [!TIP]
> Amazon AVP only supports updating the action and condition portions of a policy. If the Hexa AVP Provider detects a difference to Subject or Object, it will automatically
> convert the update into a Delete and Add operation to accomodate the change.

```shell
hexa> set policies rKO -d --file=policies.json

Ignoring AVP policyid UaN2xdjgv1Dhdpuoa3ebRU. Template updates not currently supported
0: DIF: UPDATE  [ACTION]
{
 "Meta": {
  "Version": "0.6",
  "SourceData": {
   "policyType": "STATIC",
   "principal": null,
   "resource": null
  },
  "Description": "Hexa demo canary policy",
  "Created": "2023-12-26T21:45:53.558204Z",
  "Modified": "2023-12-27T22:20:18.592795Z",
  "Etag": "20-f2ec1edc53e44c07e4d790d8936ade24b27f04eb",
  "PolicyId": "KDqUKMRNEg6aEjZ6mz9dJq",
  "PapId": "K21...93DH7z5",
  "ProviderType": "avp"
 },
 "Subject": {
  "Members": [
   "any"
  ]
 },
 "Actions": [
  {
   "ActionUri": "cedar:hexa_avp::Action::\"ReadAccount\""
  },
  {
   "ActionUri": "cedar:hexa_avp::Action::\"Transfer\""
  },
  {
   "ActionUri": "cedar:hexa_avp::Action::\"Deposit\""
  },
  {
   "ActionUri": "cedar:hexa_avp::Action::\"Withdrawl\""
  }
 ],
 "Object": {
  "resource_id": ""
 }
}
1: DIF: UNSUPPORTED 
{
 "Meta": {
  "Version": "0.6",
  "SourceData": {
   "policyType": "TEMPLATE_LINKED",
   "principal": {
    "EntityId": "gerry@strata.io",
    "EntityType": "hexa_avp::User"
   },
   "resource": {
    "EntityId": "1",
    "EntityType": "hexa_avp::account"
   }
  },
  "Description": "TestTemplate",
  "Created": "2023-11-23T19:18:16.470806Z",
  "Modified": "2023-11-23T19:18:16.470806Z",
  "Etag": "W/\"20-c7411b365c2d202b19d981a11eacf37bed72e52d\"",
  "PolicyId": "UaN2xdjgv1Dhdpuoa3ebRU",
  "PapId": "K21...93DH7z5",
  "ProviderType": "avp"
 },
 "Subject": {
  "Members": [
   "?principal"
  ]
 },
 "Actions": [
  {
   "ActionUri": "cedar:hexa_avp::Action::\"ReadAccount\""
  }
 ],
 "Object": {
  "resource_id": "cedar:?resource"
 }
}

Applying 2 policies to rKO
Update policies Y|[n]?
```

## Reconciling Policies
The `reconcile` command allows two different policy sources to be compared. Either parameter may be an PAP Alias or a file path. As with `set policies`, the report
indicates the changes against the first source that would be needed to made based on the second source (the comparison policy).

Example commands:
* `reconcile rKO policies.json` - reconciles PAP source rKO against the file policies.json
* `reconcile currentpolicies.json newpolicies.json` - reconciles to files against each other
* `reconcile rKO yHQ` - reconciles two PAP sources against each other

## Mapping Policies

At present, the Hexa Mapper can convert IDQL to and from Google Bind and Amazon Cedar formats. This includes conversion of 
IDQL condition expressions into Google Condition Expression Language(CEL) and the Cedar equivalent.

The map command is of the form:
```text
map to|from <format> <input-filepath> -o <output-path>
```

Valid `<format>` values are `gcp` and `cedar`. When the command is `map from`, the `<input-filepath>` is a file containing 
GCP Bind or AVP Cedar policy. When the command is `map to`, the `<input-filepath>` is a JSON file containing IDQL policy.


## General Help

Help is accessible at any time, using the `help` command. For more details, enter the full command such as `help add avp`.

To redirect output for any command to a file, use the `-o` option. If you would like the output to be appended to an existing file,
use the `-a` option.

Hexa CLI maintains a configuration file in order to save previously retrieved integrations and policy administration points.
By default, the path is `.hexa/config.json`. This can be overriden by setting the environment variable `$HEXA_HOME`.

Hexa can also accept redirected input in order to script a series of commands. For example:

Create a script, `avp-fetch.hexa`:
```text
add avp mycedar --file=aws-int.json
get policies 334911564 -o avp-564.idql
exit
```
> [!Tip]
> In the above script, since local PAP may not be known in advance, use the remote application object id directly in the script.

The file can then be run in a bash/shell script as follows:
```shell
export HEXA_HOME=/work/hexa-config.json
echo "Loading policy from AVP Cedar..."
hexa <avp-fetch.hexa
```
