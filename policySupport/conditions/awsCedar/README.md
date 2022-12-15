# Cedar Mapping Implementation

Implementation of mapping using [Amazon Verified Permissions (Cedar)](amazon).

* [Cedar site](https://www.cedarpolicy.com)
* [Tutorial](https://www.cedarpolicy.com/tutorial)

Cedar has a policy of the form:
```
permit(
  principal in UserGroup::"Alice/Friends",
  action in [
    Action::"readFile", 
    Action::"writeFile"
  ],
  resource in Folder::"Playa del Sol 2021"
)
when {
    principal.permitted_access_level >= resource.access_level
};

permit(
    principal,
    action == Action::"deletePhoto",
    resource == File::"photo"
)
when {
    resource.owner == principal.name
    && context.MFA == true
};
```

Negative policies with the forbid and unless clauses can be expressed:
```
forbid(
  principal,
  action == Action::"deletePhoto",
  resource == File::"Photo"
)
unless {
  context.MFA == true
}
```

`unless` and `when` are equivalent to IDQL Condition `action` values of `deny` and `allow`.