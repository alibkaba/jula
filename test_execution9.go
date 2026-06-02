package main

import (
	"context"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/types"
)

func main() {
	r := rego.New(
		rego.Module("test.rego", `package a
import rego.v1
evaluation := foo.bar("baz")`),
		rego.Query("data.a.evaluation"),
		rego.Function1(
			&rego.Function{
				Name: "foo.bar",
				Decl: types.NewFunction(types.Args(types.S), types.S),
			},
			func(b rego.BuiltinContext, op1 *ast.Term) (*ast.Term, error) {
				return nil, fmt.Errorf("my expected error")
			},
		),
	)

	pq, err := r.PrepareForEval(context.Background())
	if err != nil {
		fmt.Println("Prepare err:", err)
		return
	}
	res, err := pq.Eval(context.Background())
	if err != nil {
		fmt.Println("Eval err:", err)
	} else {
		fmt.Println("Res:", res)
	}
}
