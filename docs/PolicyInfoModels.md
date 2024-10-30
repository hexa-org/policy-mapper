# Using Policy Information Models with Hexa

## Introduction

A Policy Information Model (*PIM*) is a JSON description of an application, it's entities and entity relationships, and the
actions that may be performed against those entities. A *PIM* can be used by the pimValidate package to
validate IDQL JSON policy statements for conformance to a model. This can be useful for:
* Building a policy editor that reports both JSON syntax and policy errors in real time
* Validating policy before provisioning via Hexa
* Enumerate valid values (e.g. schema) for all parts of an IDQL policy statement.

The format for a PIM file is borrowed from [Cedar Policy Language Schema](https://docs.cedarpolicy.com/schema/human-readable-schema.html).
See also, [JSON Schema Grammar](https://docs.cedarpolicy.com/schema/json-schema-grammar.html) and [JSON Schema format](https://docs.cedarpolicy.com/schema/json-schema.html).

> [!Note]
> As [JSON Schema](https://json-schema.org) is a well-used term to define the format of a JSON structure, the Hexa Project will refer
> to policy schema as a Policy Information Model since this use of schema does not describe a JSON format but rather an 
> entity relationship model and the relevant attributes and relationships.

The code for the implementation of PIM can be found in three packages:
* `models/policyInfoModel` - contains structs and functions to parse a PIM (schema) json file
* `pkg/hexapolicy/pimValidate` - contains functions validate a `hexaPolicy.PolicyInfo` against a `policyInfoModel.SchemaType`

Note that while we've adopted Cedar Schema under the APL license, this project does not necessarily use
all the possible features available in the specification. For now, validation of policy is limited to:
* Entity types (e.g. `User`) that are valid for use as Subjects or Objects (e.g. `Photo`).
* Valid actions methods
* Which actions may be applied by what entities against which objects.

Other differences:
* IDQL uses the term `subjects` to refer to `principals`
* IDQL uses `objects` instead of `resources`
* IDQL allows multiple subjects while Cedar allows only 1
* The Hexa-OPA implementation currently does not support the full set of subject relation operations (is User in Group::"admins") even though the the validator will validate. This allows policy to be validated for provisioning against AVP.

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
