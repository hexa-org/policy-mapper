# Formats for Hexa IDQL Policy Entity Values

These variations are used to indicate different relationships for entities (subjects and objects/resources)
within IDQL policy. An entity is formatted value passed in for subjects, actions, or object.

An entity is just a type followed by a colon (:). For example:
* User:
* Photo:

To distinguish between an entity and an instance of an identity, double-quotes are used to identify the instance.  Examples:
* User:"alicesmith"
* Photo:"myVacation.jpg"

Entities can be part of one of more namespaces (e.g. PhotoApp) which are distinguished by colon separators:
* PhotoApp:Photo:"id12345.jpg"

> [!Tip]
> When expressing quoted entities within a JSON value, the quote must be escaped with a backslash (\)
> For example the json fragment: `"subjects" : ["User:\"alicesmith\"""]`

## Any or AnyAuthenticated

Used for subjects, the special purpose value of `any` (as in anything), or `anyAuthenticated` (an identified subject or User) may be used.

## Equality

Indicates a subject is an identified type with an identifier. For example, a `User` identified by `"alicesmith"`

`<type>:<id>` example `Subjects = ["User:\"alicesmith\"]`


## Type Is

Indicates matching based on the type of entity. For example, a subject that matches the entity type `AdminUser`

`<type>:`  example: `Subjects = ["AdminUser:"]`

## Type Is In

Express that a type of entity within a group. For example, a subject that is a user within the "administrators" group.

`<type>[<entity>]` example: `Subjects = ["User[Group:\"administrators\"]"]`

## In Relationship
Express that the item falls with a group entity or set of specific instances.

`[<entity>]` example: `[Group:"administrators"]`

For objects:
`[<entity>,...]` example: `[Photo:"mypic1.jpg",Photo:"mypic2.jpg"]`

Note: Because IDQL allows multiples subjects and actions, there is no need for a set unless

| Comparison | Syntax                 | IDQL                                                   | Cedar                                                |
|------------|------------------------|--------------------------------------------------------|------------------------------------------------------|
| Equality   | `<type>:<id>`          | `subjects = ["User:\"alice@example.com\"]`             | `principal == User::"alice@example.com"`             |
| Is type    | `<type>:`              | `subjects = ["User:"]`                                 | `principal is User`                                  |
| Is In      | `<type>[<entity>,...]` | `subjects = ["User[Group:\"Admins\"]"]`                | `principal is User in Group::"Admins"`               |
| In         | `[<entity>,...]`       | `subjects = [ "[Group:\"Admins\",Group:\"Employees\"]` | `principal in [Group::"Admins", Group::"Employees"]` |
