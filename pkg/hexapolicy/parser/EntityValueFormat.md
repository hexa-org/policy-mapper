# Formats for Hexa IDQL Policy Entity Values

These variations are used to indicate different matching scenarios for entities
within IDQL policy. An entity is formatted value passed in for subjects, actions, or object.

## Any or AnyAuthenticated

Used for subjects values, the special purpose value of `any` (as in anything), or `anyAuthenticated` (an identified subject or User) may be used.

## Equality

Indicates a subject is an identified type with an identifier

`<type>:<id>` example `Subjects = ["User:alicesmith"]`

Cedar: principle == User::"alicesmith"

## Type Is

Indicates a type of subject

`<type>:`  example: `User:`

## Type Is In

Express that a type of entity within a group

`<type>[<entity>]` example: `User[Group:administrators]`

## In Relationship
Express that the item falls with a group

`[<entity>]` example: `[Group:administrators]`

For objects:
`[<entity>,...]` example: `[Photo:mypic1.jpg,Photo:mypic2.jpg]`

Note: Because IDQL allows multiples subjects and actions, there is no need for a set unless

| Comparison | Syntax                 | IDQL                                           | Cedar                                                |
|------------|------------------------|------------------------------------------------|------------------------------------------------------|
| Equality   | `<type>:<id>`          | `subjects = ["User:alice@example.com"]`        | `principal == User::"alice@example.com"`             |
| Is type    | `<type>:`              | `subjects = ["User:"]`                         | `principal is User`                                  |
| Is In      | `<type>[<entity>,...]` | `subjects = ["User[Group:Admins]"]`            | `principal is User in Group::"Admins"`               |
| In         | `[<entity>,...]`       | `subjects = [ "[Group:Admins,Group:Employees]` | `principal in [Group::"Admins", Group::"Employees"]` |
