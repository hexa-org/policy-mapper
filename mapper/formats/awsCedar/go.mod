module github.com/hexa-org/policy-mapper/mapper/formats/awsCedar

go 1.20

// replace github.com/hexa-org/policy-mapper/hexaIdql v0.6.0-beta.1 => ../../../hexaIdql

// replace github.com/hexa-org/policy-mapper/mapper/conditionLangs/gcpcel v0.6.0-beta.1 => ../../conditionLangs/gcpcel

require (
	github.com/alecthomas/participle/v2 v2.1.0
	github.com/stretchr/testify v1.8.4
)

require (
	github.com/hexa-org/policy-mapper/hexaIdql v0.6.0-beta.1
	github.com/hexa-org/policy-mapper/mapper/conditionLangs/gcpcel v0.6.0-beta.1
)

require (
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/cncf/xds/go v0.0.0-20231128003011-0fa0005c9caa // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/envoyproxy/go-control-plane v0.11.1 // indirect
	github.com/google/cel-go v0.18.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	golang.org/x/exp v0.0.0-20231127185646-65229373498e // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20231127180814-3a041ad873d4 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231127180814-3a041ad873d4 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
