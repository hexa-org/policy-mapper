package conditions

import filter "github.com/hexa-org/scim-filter-parser/v2"

type ConditionInfo struct {
	Rule   string `json:"rule" validate:"required"` // in RFC7644 filter form
	Action string `json:"action"`                   // allow/deny/audit default is allow
}

type ConditionMapper interface {
	/*
		MapConditionToProvider takes an IDQL Condition expression and converts it to a string
		usable the the target provider. For examplle from RFC7644, Section-3.4.2.2 to Google Common Expression Language
	*/
	MapConditionToProvider(condition ConditionInfo) interface{}

	/*
		MapProviderToCondition take a string expression from a platform policy and converts it to RFC7644: Section-3.4.2.2.
	*/
	MapProviderToCondition(expression string) (ConditionInfo, error)
}

func ParseConditionRuleAst(condition ConditionInfo) (filter.Expression, error) {
	return filter.ParseFilter([]byte(condition.Rule))
}
