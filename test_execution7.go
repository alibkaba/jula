package main

import (
	"context"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
)

func main() {
	r := rego.New(rego.Module("test.rego", `package a
import rego.v1
evaluation := 1`), rego.Query("data.a.evaluation"), rego.Function1(&rego.Function{Name: "foo.bar", Decl: nil}, func(b rego.BuiltinContext, op1 *rego.Term) (*rego.Term, error) { return nil, fmt.Errorf("foo")}))

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
