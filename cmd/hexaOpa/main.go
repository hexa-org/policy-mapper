package main

import (
	"fmt"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"os"
	"policy-conditions/server/conditionEvaluator"
	"policy-conditions/server/hexaFilter"
)

func main() {
	rego.RegisterBuiltin2(
		&rego.Function{
			Name:             hexaFilter.PluginName,
			Decl:             types.NewFunction(types.Args(types.A, types.S), types.S),
			Memoize:          false, // function may get called several times in same query for different expressions
			Nondeterministic: true,
		},
		func(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {

			var expression, input string

			if err := ast.As(a.Value, &expression); err != nil {
				return nil, err
			}
			input = b.Value.String()

			res, err := conditionEvaluator.Evaluate(expression, input)

			return ast.BooleanTerm(res), err

		})
	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
