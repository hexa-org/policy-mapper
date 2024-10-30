# Using Policy Information Models with Hexa

## Introduction

A Policy Information Model (*PIM*) is description (in JSON form) of an application, it's entities, entity relationships, and the
actions that may be performed against those entities. A *PIM* can be used by the `pimValidate` package to
validate IDQL JSON policy statements for conformance to a model. This can be useful for:
* Building a policy editor that reports both JSON syntax and policy errors in real time
* Validating policy before provisioning via Hexa
* Looking up valid entities, attributes (e.g. schema) for all parts of an IDQL policy statement.

The format for a PIM file is based on [Cedar Policy Language Schema](https://docs.cedarpolicy.com/schema/human-readable-schema.html).
See also, [JSON Schema Grammar](https://docs.cedarpolicy.com/schema/json-schema-grammar.html) and [JSON Schema format](https://docs.cedarpolicy.com/schema/json-schema.html).

> [!Note]
> [JSON Schema](https://json-schema.org) is a well-used term to define the format of a JSON document. Because Cedar JSON Schema has
> nothing to do with JSON Schema, the Hexa Project refers policy schema as **Policy Information Models**.  

The code for the implementation of Hexa PIM can be found in these packages:
* `models/policyInfoModel` - contains structs and functions to parse a PIM (schema) json file
* `pkg/hexapolicy/pimValidate` - contains functions validate a `hexaPolicy.PolicyInfo` against a `policyInfoModel.SchemaType`

Note that the implementation of Cedar schema is preliminary and not all features are supported. For now, policy validation is limited to:
* Entity types (e.g. `User`) that are valid for use as Subjects or Objects (e.g. `Photo`).
* Valid actions methods
* Which actions may be applied by what entities against which objects.

Other differences:
* IDQL uses the term `subjects` to refer to `principals`
* IDQL uses `objects` instead of `resources`
* IDQL allows multiple subjects while Cedar allows only 1
* The Hexa-OPA implementation currently does not support the full set of subject relation operations (is User in Group::"admins") even though the the validator will validate. This allows policy to be validated for provisioning against AVP.

Interoperability:
* Hexa is able to parse Cedar Schema files directly
* Cedar Policy that is mapped to IDQL will validate against the original Cedar Schema (e.g. try the [Cedar Playground Apps](https://www.cedarpolicy.com/en/playground))
## Playing with Models

The Hexa CLI tool has been extended to load and show policy models as well as to validate policy.

The `load model` command takes a file path as its parameter, reads and confirms what namespaces are loaded.
```bash
hexa> load model ./examples/policyInfoModels/photoSchema.json
Namespaces loaded:
        PhotoApp
hexa>  
```

To display the namespace use the `show model` command
```bash
hexa> show model *

Namespace: PhotoApp
===================

Entities:
Photo MemberOf: [Album Account]
-------------------------------
account                 Entity
private                 Boolean

Album
-----
No attributes defined

Account
-------
No attributes defined

User MemberOf: [UserGroup]
--------------------------
userId                  String
personInformation       PersonType

UserGroup
---------
No attributes defined

Common Types:

ContextType
-----------
ip                      Extension
authenticated           Boolean

PersonType
----------
age                     Long
name                    String

Actions:

viewPhoto, applies to
 Subjects ->    User, UserGroup
 Objects ->     Photo
createPhoto, applies to
 Subjects ->    User, UserGroup
 Objects ->     Photo
listPhotos, applies to
 Subjects ->    User, UserGroup
 Objects ->     Photo
hexa>  
```

The `validate policy` command takes a namespace (e.g. PhotoApp) and a policy file path to parse and validate one or more policies:
```bash
hexa> validate policy PhotoApp ./examples/policyInfoModels/photoidql.json
Policy-0...Valid

Policy-1...Valid
hexa>
```

If for example, the object of a policy referred to an invalid type (e.g. BadPhoto), the validator will return errors similar this:
```bash
hexa> validate policy PhotoApp ./examples/policyInfoModels/photoidql.json
Policy-0
  invalid object entity type: PhotoApp:BadPhoto
  policy cannot be applied to object type "PhotoApp:BadPhoto:"vacationPhoto.jpg"", must be one of ["Photo"]
Policy-1...Valid
```
