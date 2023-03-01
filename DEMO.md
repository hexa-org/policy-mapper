# HexaMapper Utility

After cloning the project, complete the following to build the command

```shell
git clone https://github.com/hexa-org/policy-mapper.git
cd policy-mapper
go mod download
go mod tidy
cd cmd/mapper
go build
```

This will build the executable hexaMapper.  


## Map to AWS Cedar

```shell
./mapper -t=awscedar examples/idqlAlice.json
```

This returns the result:
```text
permit (
    principal == User::"alice",
    action == Action::"view",
    resource in Photo::"VacationPhoto94.jpg"
);
permit (
    principal == User::"stacey",
    action == Action::"view",
    resource
)
when { resource in "Account:stacey" };
```

## Map To Google Bind
```shell
./mapper -t=gcpBind examples/idqlAlice.json
```

```json
[
  {
    "resource_id": "cedar:Photo::\"VacationPhoto94.jpg\"",
    "bindings": [
      {
        "members": [
          "User:\"alice\""
        ]
      }
    ]
  },
  {
    "resource_id": "",
    "bindings": [
      {
        "condition": {
          "expression": "resource in \"Account:stacey\""
        },
        "members": [
          "User:\"stacey\""
        ]
      }
    ]
  }
]
```

# Map Cedar to IDQL
```text
permit(
principal == User::"bob",
action in [Action::"view", Action::"comment"],
resource in Photo::"trip"
) unless{
resource.tag == "private" };
```

```shell
./mapper -t=awsCedar -p examples/cedarSingle.txt
```

```json
{
  "policies": [
    {
      "Meta": {
        "Version": "0.5"
      },
      "Actions": [
        {
          "ActionUri": "cedar:Action::\"view\""
        },
        {
          "ActionUri": "cedar:Action::\"comment\""
        }
      ],
      "Subject": {
        "Members": [
          "User:\"bob\""
        ]
      },
      "Object": {
        "resource_id": "cedar:Photo::\"trip\""
      },
      "Condition": {
        "Rule": "not(resource.tag eq \"private\")",
        "Action": "permit"
      }
    }
  ]
}

```