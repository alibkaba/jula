package main

import (
	"context"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
)

func main() {
	r := rego.New(rego.Module("test.rego", `package a
import rego.v1
evaluation := 1`), rego.Query("data.a.evaluation"), rego.Unknowns([]string{"data.a.b.c"}))

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
