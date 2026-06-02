package main

import (
	"context"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
)

func main() {
	r := rego.New(rego.Module("test.rego", "package a\nimport rego.v1\nx = 1 / 0"), rego.Query("data.a.x"))
	pq, err := r.PrepareForEval(context.Background())
	if err != nil {
		fmt.Println("Prepare err:", err)
		return
	}
	_, err = pq.Eval(context.Background())
	if err != nil {
		fmt.Println("Eval err:", err)
	}
}
